import io
import codecs
import string
import nrs
from builtins import bytes
from . import fileform, strings
from . import disassembler, method
from .fileform import NB_BGFONT, NB_DATA, NB_PAGES, NB_ENTRIES, NB_ENTRIES, \
                      NB_STRINGS, NB_SECTIONS, NB_CTLCOLORS, NB_LANGTABLES, \
                      inflate_header
from . import nsifiledump

def _flatten(l):
    return [i for sl in l for i in sl]

class HeaderNotFound(Exception):
    pass

class NSIS:
    @staticmethod
    def from_path(path):
        with open(path, 'rb') as fd:
            return NSIS(fd)

    def __init__(self, fd):
        """
        Create a new NSIS instance given an NSIS installer loaded in |fd|.
        """
        self._block_cache = {}
        self._pe = None

        self.file_data = bytes(fd.read())
        fd.seek(0)

        self.fd = fd
        """ Parsed installer file. """

        self.firstheader = None
        """ Firstheader structure found at the beginning of the NSIS blob. """

        self.header = None
        """
        Header structure found at the beginning of the uncompressed NSIS blob.
        """

        self.sections = []
        """ List of sections installable by the installer. """

        self.entries = []
        """ Installer instructions. """

        self.pages = []
        """ Installer pages. """

        self.is_unicode = False

        self.is_solid = False

        self.after_header = None
        
        self.data_offset = -1
        
        self.methods = dict()
        
        self.compressor = ''

        if not self._parse():
            raise HeaderNotFound()
        self.is_unicode = self.block(NB_STRINGS)[0] == 0 and self.block(NB_STRINGS)[1] == 0
        self.version_major, self.version_minor = self._detect_version()
        self._find_methods()

    def get_method_by_offset(self, offset):
        if offset in self.methods:
            return self.methods[offset]
        return None
    
    def disassemble_method(self, obj):
        if isinstance(obj, method.NsisMethod):
            return disassembler.NsisDisassembler(self, obj.get_method_offset(), obj.get_method_end())
        mobj = self.get_method_by_offset(obj)
        return disassembler.NsisDisassembler(self, mobj.get_method_offset(), mobj.get_method_end())


    def get_string(self, address):
        """ Returns an NSIS expanded string given its |address|. """
        if self.is_unicode:
            return self._parse_string(address * 2)[0]
        return self._parse_string(address)[0]

    def get_raw_string(self, address):
        """ Returns a raw NSIS string given its |address|. """
        string = bytearray()
        start = address
        if not self.is_unicode:
            for x in range(start, len(self.block(NB_STRINGS))):
                c = self.block(NB_STRINGS)[x]
                string.append(c)
                if c == 0:
                    break
        else:
            for x in range(start, len(self.block(NB_STRINGS)), 2):
                c = int.from_bytes(self.block(NB_STRINGS)[x:x+2], 'little')
                c1, c2 = self.block(NB_STRINGS)[x:x+2]
                string.append(c1)
                string.append(c2)
                if c == 0:
                    break
        return string

    def get_all_strings(self):
        """ Returns all NSIS strings extracted from the strings section. """
        string_block_size = len(self.block(NB_STRINGS))
        offset = 0
        strings = []
        while offset < string_block_size:
            string, processed = self._parse_string(offset)
            if string:
                strings.append(string)
            offset += processed

        return strings

    def get_all_raw_strings(self):
        """
        Returns all raw NSIS strings extracted from the strings section.
        """
        string_block_size = len(self.block(NB_STRINGS))
        offset = 0
        if self.is_unicode:
            offset += 2
        strings = []
        while offset < string_block_size:
            string = self.get_raw_string(offset)
            if string:
                strings.append(string)
            offset += len(string)
        return strings
    
    def get_langtable_lang_id(self):
        num_entries = self.header.blocks[NB_LANGTABLES].num
        block_data = self.block(NB_LANGTABLES)
        langtable_size = self.header.langtable_size
        for x in range(num_entries):
            p = langtable_size * x
            lang_id = int.from_bytes(block_data[p:p+2], 'little')
            return lang_id
        return None
    
    def get_langtable_strings(self):
        num_entries = self.header.blocks[NB_LANGTABLES].num
        block_data = self.block(NB_LANGTABLES)
        langtable_size = self.header.langtable_size
        num_strings = (langtable_size - 10) // 4
        result = list()
        for x in range(num_entries):
            p = langtable_size * x
            for y in range(num_strings):
                val_ptr = p + 10 + (y * 4)
                val = int.from_bytes(block_data[val_ptr:val_ptr+4], 'little')
                if val != 0:
                    result.append(self.get_string(val))
                else:
                    if self.is_unicode:
                        result.append(strings.UnicodeString(b''))
                    else:
                        result.append(strings.String(b''))
        return result

    def block(self, n):
        """ Return a block data given a NB_* enum |n| value. """
        #Theres a few special cases for this where blocks can be better defined.
        if n == NB_DATA:
            if not self.is_solid:
                return self.file_data[self.data_offset:]
            return self.firstheader._raw_header[self.firstheader.u_size:]
        elif n == NB_ENTRIES:
            #NB_ENTRIES size will be num * 28.
            start = self.header.blocks[n].offset
            block_size = self.header.blocks[n].num * 28 #Instruction Length is always 28.
            return self.firstheader._raw_header[start:start+block_size]
        elif n == NB_PAGES:
            start = self.header.blocks[n].offset
            end = start + (self.header.blocks[n].num * fileform.PAGE_SIZE)
            return self.firstheader._raw_header[start:end]
        if n not in self._block_cache:
            start = self.header.blocks[n].offset
            try:
                end = next(b.offset for b
                        in self.header.blocks[n+1:] if b.offset > 0)
            except StopIteration:
                end = len(self.header.blocks)
            self._block_cache[n] = self.firstheader._raw_header[start:end]
        return self._block_cache[n]
    
    def block_offset(self, n):
        return self.header.blocks[n].offset

    def size(self):
        return len(self.firstheader._raw_header)

    def close(self):
        if self._pe is not None:
            self._pe.close()

    def _detect_version(self):
        # Try to parse string and get
        nsis2_codes = 0
        nsis3_codes = 0
        nsis2_unicode_codes = 0
        for string in self.get_all_raw_strings():
            c = string[0]
            if len(string) > 1 and c <= 0x3 and string[1] == 0xE0:
                nsis2_unicode_codes += 1
            elif c <= 4:
                nsis3_codes += 1
            elif c >= 252:
                nsis2_codes += 1
        if nsis2_codes > nsis3_codes or nsis2_unicode_codes > nsis3_codes:
            return '2', '?'
        else:
            return '3', '?'
        
    def _find_methods(self):
        #first populate all potential etnrypoints

        def canonize_name(name):
            """ Limit names to a subset of ascii character. """
            allowed_name_char = string.ascii_letters + string.digits + '$'

            return str(''.join([c if c in allowed_name_char else '_' for c in name]))
        for i, section in enumerate(self.sections):
            if section.code == disassembler.PTR_NONE or section.code == -1:
                continue
            name = self.get_string(section.name_ptr)
            if not name:
                name = '_section' + str(i)
            ea = nrs.entry_to_offset(section.code)
            cname = canonize_name(name)
            self.methods[ea] = method.NsisMethod(self, cname, ea)
        
        for i, page in enumerate(self.pages):
            for fn in ['prefunc', 'showfunc', 'leavefunc']:
                addr = getattr(page, fn)
                if addr != disassembler.PTR_NONE and section.code != -1:
                    name = '_page_{}_{}'.format(i, fn)
                    ea = nrs.entry_to_offset(addr)
                    self.methods[ea] = method.NsisMethod(self, name, ea)

        for event in ['Init', 'InstSuccess', 'InstFailed', 'UserAbort', 'GUIInit',
                    'GUIEnd', 'MouseOverSection', 'VerifyInstDir', 'SelChange',
                    'RebootFailed']:
            addr = getattr(self.header, 'code_on'+event)
            if addr != disassembler.PTR_NONE and addr != -1:
                name = '_on' + event
                ea = nrs.entry_to_offset(addr)
                self.methods[ea] = method.NsisMethod(self, name, ea)

        #disassemble the entire entries block to allow for Call methods to be populated.
        disassembler.NsisDisassembler(self, 0, 28 * self.header.blocks[NB_ENTRIES].num)
        sort_list = list(self.methods.items())
        def sort_func(item):
            return item[0]
        
        sort_list.sort(key=sort_func)
        for x in range(len(sort_list)):
            if x == len(sort_list) - 1:
                func_end = len(self.block(NB_ENTRIES))
            else:
                func_end = sort_list[x+1][0]
            sort_list[x][1].set_method_end(func_end)
        self.methods = dict(sort_list)

    def dump_script(self):
        dumper = nsifiledump.NsiFileDumper(self)
        return dumper.process()
            
    def get_extracted_file(self, identifier):
        """
        Obtain the file that will be dropped by an ExtractFile instruction.
        """
        data_block = self.block(NB_DATA)
        #Using force_compressor here avoids a whole bunch of issues - compression identification isnt the best but it will always be the same as the header.
        return inflate_header(io.BytesIO(data_block), identifier, is_header=False, force_compressor=self.compressor)[0]

    def _parse_string(self, address):
        """ Returns an NSIS expanded string given its |address|. """
        return strings.decode(self.block(NB_STRINGS), self, address, self.version_major, self.is_unicode)

    def _parse(self):
        self.firstheader = fileform._find_firstheader(self.fd)
        if self.firstheader is None:
            return False

        self.header = fileform._extract_header(self, self.firstheader)
        if self.header.blocks[NB_PAGES].num != 0:
            self.pages = fileform._parse_pages(
                    self.block(NB_PAGES),
                    self.header.blocks[NB_PAGES].num)
        else:
            self.pages = list()

        if self.header.blocks[NB_SECTIONS].num != 0:
            self.sections = fileform._parse_sections(
                    self,
                    self.block(NB_SECTIONS),
                    self.header.blocks[NB_SECTIONS].num)
        else:
            self.sections = list()

        if self.header.blocks[NB_ENTRIES].num != 0:
            self.entries = fileform._parse_entries(
                    self.block(NB_ENTRIES),
                    self.header.blocks[NB_ENTRIES].num)
        else:
            self.entries = list()
        return True
