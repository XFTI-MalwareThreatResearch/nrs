import struct
import zlib
import os
from builtins import bytes
from collections import namedtuple

# First header flags.
FH_FLAGS_UNINSTALL = 1
FH_FLAGS_SILENT = 2
FH_FLAGS_NO_CRC = 4
FH_FLAGS_FORCE_CRC = 8

# First header signature.
FH_SIG = 0xDEADBEEF
FH_MAGICS = b'NullsoftInst'

# Common flags.
CH_FLAGS_DETAILS_SHOWDETAILS = 1
CH_FLAGS_DETAILS_NEVERSHOW = 2
CH_FLAGS_PROGRESS_COLORED = 4
CH_FLAGS_SILENT = 8
CH_FLAGS_SILENT_LOG = 16
CH_FLAGS_AUTO_CLOSE = 32
CH_FLAGS_DIR_NO_SHOW = 64
CH_FLAGS_NO_ROOT_DIR = 128
CH_FLAGS_COMP_ONLY_ON_CUSTOM = 256
CH_FLAGS_NO_CUSTOM = 512

# Block type enumaration.
NB_PAGES = 0
NB_SECTIONS = 1
NB_ENTRIES = 2
NB_STRINGS = 3
NB_LANGTABLES = 4
NB_CTLCOLORS = 5
NB_BGFONT = 6
NB_DATA = 7

# Callback enumeration.
CB_ONINIT = 0
CB_ONINSTSUCCESS = 1
CB_ONINSTFAILED = 2
CB_ONUSERABORT = 3
#ifdef NSIS_CONFIG_ENHANCEDUI_SUPPORT
CB_ONGUIINIT = 4
CB_ONGUIEND = 5
CB_ONMOUSEOVERSECTION = 6
#endif NSIS_CONFIG_ENHANCEDUI_SUPPORT
CB_ONVERIFYINSTDIR = 7
#ifdef NSIS_CONFIG_COMPONENTPAGE
CB_ONSELCHANGE = 8
#endif NSIS_CONFIG_COMPONENTPAGE
#ifdef NSIS_SUPPORT_REBOOT
CB_ONREBOOTFAILED = 9
#endif NSIS_SUPPORT_REBOOT

# Section flags.
SF_SELECTED = 1
SF_SECGRP = 2
SF_SECGRPEND = 4
SF_BOLD = 8
SF_RO = 16
SF_EXPAND = 32
SF_PSELECTED = 64
SF_TOGGLED = 128
SF_NAMECHG = 256

# Page window proc.
#ifdef NSIS_CONFIG_LICENSEPAGE
PWP_LICENSE = 0
#endif NSIS_CONFIG_LICENSEPAGE
#ifdef NSIS_CONFIG_COMPONENTPAGE
PWP_SELCOM = 1
#endif NSIS_CONFIG_COMPONENTPAGE
PWP_DIR = 2
PWP_INSTFILES = 3
#ifdef NSIS_CONFIG_UNINSTALL_SUPPORT
PWP_UNINST = 4
#endif NSIS_CONFIG_UNINSTALL_SUPPORT
PWP_COMPLETED = 5
PWP_CUSTOM = 6

# Page flags.
PF_LICENSE_SELECTED = 1
PF_NEXT_ENABLE = 2
PF_CANCEL_ENABLE = 4
PF_BACK_SHOW = 8
PF_LICENSE_STREAM = 16
PF_LICENSE_FORCE_SELECTION = 32
PF_LICENSE_NO_FORCE_SELECTION = 64
PF_NO_NEXT_FOCUS = 128
PF_BACK_ENABLE = 256
PF_PAGE_EX = 512
PF_DIR_NO_BTN_DISABLE = 1024

# Text and background color.
CC_TEXT = 1
CC_TEXT_SYS = 2
CC_BK = 4
CC_BK_SYS = 8
CC_BKB = 16

# Delete flags.
DEL_DIR = 1
DEL_RECURSE = 2
DEL_REBOOT = 4
DEL_SIMPLE = 8

NSIS_MAX_STRLEN = 1024
NSIS_MAX_INST_TYPES = 32

MAX_ENTRY_OFFSETS = 6

BLOCKS_COUNT = 8

PAGE_SIZE = 16 * 4

# First header with magic constant found in any NSIS executable.
class FirstHeader(namedtuple('FirstHeader', ['flags', 'siginfo', 'magics',
                                             'u_size', 'c_size'])):
    header_offset = 0
    data_offset = 0
    header = None

# Compressed header with the installer's sections and properties.
class Header:
    def __init__(self):
        self.blocks = []
        self.install_types = []
        self.flags = []
        self.install_reg_rootkey = 0
        self.install_reg_key_ptr = 0
        self.install_reg_value_ptr = 0
        self.bg_color1 = 0
        self.bg_color2 = 0
        self.bg_textcolor = 0
        self.lb_bg = 0
        self.lb_fg = 0
        self.langtable_size = 0
        self.license_bg = 0
        self.code_onInit = 0
        self.code_onInstSuccess = 0
        self.code_onInstFailed = 0
        self.code_onUserAbort = 0
        self.code_onGUIInit = 0
        self.code_onGUIEnd = 0
        self.code_onMouseOverSection = 0
        self.code_onVerifyInstDir = 0
        self.code_onSelChange = 0
        self.code_onRebootFailed = 0
        self.install_directory_ptr = 0
        self.install_directory_auto_append = 0
        self.str_uninstchild = 0
        self.str_uninstcmd = 0
        self.str_wininit = 0
        self.raw_data = None

    @staticmethod
    def get_uint32(data):
        return int.from_bytes(data[:4], 'little', signed=False)

    @staticmethod
    def get_int32(data):
        return int.from_bytes(data[:4], 'little', signed=True)

    @staticmethod
    def parse(inflated_data, firstheader):
        #Data is off by 4 here.
        header = Header()
        if Header.get_int32(inflated_data) == firstheader.u_size:
            inflated_data = inflated_data[4:]
        header.raw_data = inflated_data
        current_offset = 0
        # Parse the block headers.
        is_64bit = False
        if firstheader.u_size < 4 + 12 * 8:
            is_64bit = False
        else:
            is_64bit = True
            for k in range(0, 8):
                num_data = inflated_data[4 + 12 * k + 4: ][:4]
                if len(num_data) == 0:
                    continue
                num = int.from_bytes(num_data, 'little')
                if num != 0:
                    is_64bit = False
        bhoSize = 8
        if is_64bit:
            bhoSize = 12
        block_headers = []
        for i in range(BLOCKS_COUNT):
            if not is_64bit:
                header_offset = 4 + (i * _blockheader_pack.size)
                block_header = BlockHeader._make(_blockheader_pack.unpack_from(
                    inflated_data[header_offset:]))
                block_headers.append(block_header)
            else:
                header_offset = 4 + (i * _blockheader64_pack.size)
                block_header = BlockHeader._make(_blockheader64_pack.unpack_from(
                    inflated_data[header_offset:]))
                block_headers.append(block_header)
        header.blocks = block_headers

        header.flags = Header.get_int32(inflated_data[current_offset:current_offset + 4])
        current_offset += 4
        numBhs = 8
        if bhoSize == 8 and header.blocks[NB_PAGES].offset == 276:
            numBhs = 7
        params_offset = 4 + (bhoSize * numBhs)
        header.install_reg_rootkey == Header.get_int32(inflated_data[params_offset:params_offset+4])
        params_offset += 4
        header.install_reg_key_ptr = Header.get_int32(inflated_data[params_offset:params_offset+4])
        params_offset += 4
        header.install_reg_value_ptr = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.bg_color1 = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.bg_color2 = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.bg_textcolor = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.lb_bg = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.lb_fg = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.langtable_size = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.license_bg = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.code_onInit = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.code_onInstSuccess = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.code_onInstFailed = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.code_onUserAbort = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.code_onGUIInit = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.code_onGUIEnd = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.code_onMouseOverSection = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.code_onVerifyInstDir = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        header.code_onSelChange = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4
        if header.blocks[NB_PAGES].offset != 276:
            header.code_onRebootFailed = Header.get_int32(inflated_data[params_offset:])
            params_offset += 4
        else:
            header.code_onRebootFailed = 0

        for x in range(NSIS_MAX_INST_TYPES + 1):
            header.install_types.append(Header.get_int32(inflated_data[params_offset:]))
            params_offset += 4
        header.install_directory_ptr = Header.get_int32(inflated_data[params_offset:])
        params_offset += 4

        if header.blocks[NB_PAGES].offset >= 288:
            header.install_directory_auto_append = Header.get_int32(inflated_data[params_offset:])
            params_offset += 4
            header.str_uninstchild = Header.get_int32(inflated_data[params_offset:])
            params_offset += 4
            header.str_uninstcmd = Header.get_int32(inflated_data[params_offset:])
            params_offset += 4
            header.str_wininit = Header.get_int32(inflated_data[params_offset:])
            params_offset += 4
        else:
            header.install_directory_auto_append = 0
            header.str_uninstchild = 0
            header.str_uninstcmd = 0
            header.str_wininit = 0
        return header

# Block header with location and size.
BlockHeader = namedtuple('BlockHeader', 'offset num')

Section = namedtuple('Section', [
        'name_ptr', # Initial name pointer.
        'install_types', # Bitset for the install types.
        'flags', # Flags from SF_*.
        'code', # Code location.
        'code_size', # Size of the code.
        'size_kb',
        'name' # Empty for invisible sections.
    ])

class Entry(namedtuple('Entry', [
            'which', # EW_* enum.
            'raw_offsets', # Meaning depends on |which|.
        ])):
    offsets = []


class Page(namedtuple('Page', [
            'dlg_id', # Dialog resource ID.
            'wndproc_id',
            #ifdef NSIS_SUPPORT_CODECALLBACKS
                'prefunc', # Called before the page is created.
                'showfunc', # Called right before the page is shown.
                'leavefunc', # Called when the user leaves the page.
            'flags',
            'caption',
            'back',
            'next',
            'clicknext',
            'cancel',
            'raw_params'
        ])):
    params = []

CtlColors32 = namedtuple('CtlColors32', [
        'text',
        'bkc',
        'lbStyle',
        'bkb',
        'bkmode',
        'flags'
    ])


_firstheader_pack = struct.Struct("<II12sII")
_header_pack = struct.Struct("<I64s20I{}s5I".format(4*(NSIS_MAX_INST_TYPES+1)))
_blockheader_pack = struct.Struct("<II")
_blockheader64_pack = struct.Struct("<QI")
_section_pack = struct.Struct("<6I{}s".format(NSIS_MAX_STRLEN))
_entry_pack = struct.Struct("<I{}s".format(MAX_ENTRY_OFFSETS*4))
_page_pack = struct.Struct("<11I20s")
_ctlcolors32_pack = struct.Struct("<6I")

def _find_firstheader(nsis_file):
    firstheader_offset = 0
    pos = 0
    while True:
        chunk = nsis_file.read(32768 if firstheader_offset else 512)
        if len(chunk) < _firstheader_pack.size:
            return None

        if firstheader_offset == 0:
            firstheader = FirstHeader._make(
                    _firstheader_pack.unpack_from(chunk))
            firstheader.header_offset = pos
            firstheader.data_offset = pos + _firstheader_pack.size

            if firstheader.siginfo == FH_SIG and \
                    firstheader.magics == FH_MAGICS:
                # NSIS header found.
                return firstheader

        pos += len(chunk)

def _is_lzma(data):
    def _is_lzma_header(data):
        return data[0:3] == bytes([0x5d, 0, 0]) \
                and data[5] == 0 \
                and (data[6] & 0x80 == 0)
    return (_is_lzma_header(data) or (data[0] <= 1 and _is_lzma_header(data[1:])))

def _is_bzip2(data):
    return data[0] == 0x31 and data[1] < 0xe

def _zlib(f, size, is_header):
    data = f.read(size)
    from nrs.ext import zlibnsis as zlib_nsis
    try:
        #The goal is to use python's zlib library due to speed and security, but if not we can use the NSIS version.
        result = bytes(zlib.decompress(data, -zlib.MAX_WBITS))
        #Theres some cases with NSIS-2-Unicode binaries where zlib doesnt work.
    except Exception as e:
        result = bytes(zlib_nsis.decompress(data))
    return result, size

def _bzip2(f, size, is_header):
    from nrs.ext import bzlib
    data = f.read(size)
    return bytes(bzlib.decompress(data)), size

def _lzma(f, size, is_header):
    import lzma
    data = f.read(size)
    props = lzma._decode_filter_properties(lzma.FILTER_LZMA1, data[0:5])
    decomp = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[props])
    output = decomp.decompress(data[5:])
    return output, len(data) - len(decomp.unused_data)

def inflate_header(nsis_file, data_offset, is_header=True, force_compressor=None):
    nsis_file.seek(0, os.SEEK_END)
    file_size = nsis_file.tell()
    if data_offset > file_size:
        return None, 0, False, None, 0
    nsis_file.seek(data_offset)
    if is_header:
        chunk = bytes(nsis_file.read(0xc))
    else:
        chunk = bytes(nsis_file.read(4))
    data_size = struct.unpack_from('<I', chunk)[0]
    if (data_size & 0x80000000) == 0:
        if (data_offset + data_size + 4) > file_size:
            return None, 0, False, None, 0
        return nsis_file.read(data_size), data_size, False, None, data_offset + 4 + data_size
    solid = True
    decoder = None
    compressor = ''
    if force_compressor is None:
        if is_header:
            if _is_lzma(chunk):
                decoder = _lzma
                compressor = 'lzma'
            elif chunk[3] == 0x80:
                solid = False
                if _is_lzma(chunk[4:]):
                    decoder = _lzma
                    compressor = 'lzma'
                elif _is_bzip2(chunk[4:]):
                    decoder = _bzip2
                    compressor = 'bzip2'
                else:
                    decoder = _zlib
                    compressor = 'zlib'
            elif _is_bzip2(chunk):
                decoder = _bzip2
                compressor = 'bzip2'
            else:
                decoder = _zlib
                compressor = 'zlib'
    else:
        compressor = force_compressor
        if force_compressor == 'lzma':
            decoder = _lzma
        elif force_compressor == 'bzip2':
            decoder = _bzip2
        elif force_compressor == 'zlib':
            decoder = _zlib
        else:
            raise Exception('Unknown compressor.')
    if solid and is_header:
        deflated_data = nsis_file.seek(data_offset)
    else:
        nsis_file.seek(data_offset+4)
        data_size &= 0x7fffffff

    if compressor != 'lzma' and (nsis_file.tell() + data_size) > file_size:
        return None, 0, False, None, 0
    if compressor == 'lzma':
        data_size = -1
    inflated_data, data_size = decoder(nsis_file, data_size, is_header)
    after_header = None
    return inflated_data, data_size, solid, after_header, compressor, data_offset + 4 + data_size

def _extract_header(nsis_file, firstheader):
    ptr = nsis_file
    nsis_file = nsis_file.fd
    inflated_data, data_size, solid, after_header, compressor, post_pos = inflate_header(nsis_file, firstheader.data_offset)
    header = Header.parse(inflated_data, firstheader)
    firstheader.header = header
    firstheader._raw_header = header.raw_data
    firstheader._raw_header_c_size = len(header.raw_data)
    ptr.is_solid = solid
    ptr.after_header = after_header
    ptr.data_offset = post_pos
    ptr.compressor = compressor

    return header

def _extract_block(nsis_file, firstheader, block_id):
    header = firstheader.header
    if block_id == NB_DATA:
        nsis_file.seek(firstheader.data_offset + firstheader._raw_header_c_size)
        return nsis_file.read()

    return firstheader._raw_header[header.blocks[block_id].offset:]

def _parse_sections(nsis_file, block, n):
    section_size = (nsis_file.block_offset(NB_ENTRIES) - nsis_file.block_offset(NB_SECTIONS)) // nsis_file.header.blocks[NB_SECTIONS].num
    sections = list()
    for i in range(n):
        section = Section._make(_section_pack.unpack_from(block[i * section_size:]))
        sections.append(section)
    return sections

def _parse_entries(block, n):
    bsize = _entry_pack.size
    entries = []
    for i in range(n):
        entry = Entry._make(_entry_pack.unpack_from(block[i * bsize:]))
        # Parse the install types.
        entry.offsets = [
            struct.unpack_from('<I', entry.raw_offsets[j:])[0]
                for j in range(0, len(entry.raw_offsets), 4)]
        entries.append(entry)

    return entries

def _parse_pages(block, n):
    bsize = _page_pack.size
    pages = []
    for i in range(n):
        page = Page._make(_page_pack.unpack_from(block[i * bsize:]))
        # Parse the install types.
        page.params = [
            struct.unpack_from('<I', page.raw_params[j:])[0]
                for j in range(0, len(page.raw_params), 4)]
        pages.append(page)

    return pages

