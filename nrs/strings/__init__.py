from builtins import bytes
import struct
from . import nsis2, nsis3, nsis2_unicode
from .. import fileform

SYSVAR_NAMES = {
    20: 'COMMANDLINE',
    21: 'INSTALLDIR',
    22: 'OUTPUTDIR',
    23: 'EXEDIR',
    24: 'LANGUAGE',
    25: 'TEMPDIR',
    26: 'PLUGINSDIR',
    27: 'EXEPATH',
    28: 'EXEFILE',
    29: 'HWNDPARENT',
    30: 'CLICKNEXT',
}

ESCAPE_MAP = {
    0x9: b'$\\t',
    0xa: b'$\\n',
    0xd: b'$\\r',
    0x22: b'$\\"',
    0x24:b'$$',
}

UNICODE_ESCAPE_MAP = {
    0x9: '$\\t'.encode('utf-16le'),
    0xa: '$\\n'.encode('utf-16le'),
    0xd: '$\\r'.encode('utf-16le'),
    0x22: '$\\"'.encode('utf-16le'),
    0x24: '$$'.encode('utf-16le'),
}

SHELL_STRINGS = [
    "DESKTOP",     # +
    "INTERNET",    # +
    "SMPROGRAMS",  # CSIDL_PROGRAMS
    "CONTROLS",    # +
    "PRINTERS",    # +
    "DOCUMENTS",   # CSIDL_PERSONAL
    "FAVORITES",   # CSIDL_FAVORITES
    "SMSTARTUP",   # CSIDL_STARTUP
    "RECENT",      # CSIDL_RECENT
    "SENDTO",      # CSIDL_SENDTO
    "BITBUCKET",   # +
    "STARTMENU",
    "",          # CSIDL_MYDOCUMENTS = CSIDL_PERSONAL
    "MUSIC",       # CSIDL_MYMUSIC
    "VIDEOS",      # CSIDL_MYVIDEO
    "",
    "DESKTOP",     # CSIDL_DESKTOPDIRECTORY
    "DRIVES",      # +
    "NETWORK",     # +
    "NETHOOD",
    "FONTS",
    "TEMPLATES",
    "STARTMENU",   # CSIDL_COMMON_STARTMENU
    "SMPROGRAMS",  # CSIDL_COMMON_PROGRAMS
    "SMSTARTUP",   # CSIDL_COMMON_STARTUP
    "DESKTOP",     # CSIDL_COMMON_DESKTOPDIRECTORY
    "APPDATA",     # CSIDL_APPDATA         !!! "QUICKLAUNCH"
    "PRINTHOOD",
    "LOCALAPPDATA",
    "ALTSTARTUP",
    "ALTSTARTUP",  # CSIDL_COMMON_ALTSTARTUP
    "FAVORITES",   # CSIDL_COMMON_FAVORITES
    "INTERNET_CACHE",
    "COOKIES",
    "HISTORY",
    "APPDATA",     # CSIDL_COMMON_APPDATA
    "WINDIR",
    "SYSDIR",
    "PROGRAM_FILES", # +
    "PICTURES",    # CSIDL_MYPICTURES
    "PROFILE",
    "SYSTEMX86", # +
    "PROGRAM_FILESX86", # +
    "PROGRAM_FILES_COMMON", # +
    "PROGRAM_FILES_COMMONX86", # +  CSIDL_PROGRAM_FILES_COMMONX86
    "TEMPLATES",   # CSIDL_COMMON_TEMPLATES
    "DOCUMENTS",   # CSIDL_COMMON_DOCUMENTS
    "ADMINTOOLS",  # CSIDL_COMMON_ADMINTOOLS
    "ADMINTOOLS",  # CSIDL_ADMINTOOLS
    "CONNECTIONS", # +
    "",
    "",
    "",
    "MUSIC",       # CSIDL_COMMON_MUSIC
    "PICTURES",    # CSIDL_COMMON_PICTURES
    "VIDEOS",      # CSIDL_COMMON_VIDEO
    "RESOURCES",
    "RESOURCES_LOCALIZED",
    "COMMON_OEM_LINKS", # +
    "CDBURN_AREA",
    "", # unused
    "COMPUTERSNEARME", # +
]

class Symbol(object):
    def is_reg(self):
        return False
    def is_var(self):
        return False
    def is_nvar(self):
        return False
    def is_lang_code(self):
        return False
    def is_shell(self):
        return False
    def is_string(self):
        return False

class Label(Symbol):
    def __init__(self, offset):
        self.__offset = offset
    
    def __str__(self):
        return 'label_{}'.format(hex(self.__offset).lstrip('0x'))

#TODO: https:#github.com/Noice2k/NsisDecompiler
class NVar(Symbol):
    def __init__(self, nvar):
        self.nvar = nvar

    def __str__(self):
        if self.nvar in SYSVAR_NAMES:
            return '$' + SYSVAR_NAMES[self.nvar]
        elif self.nvar < 10:
            return '$' + str(self.nvar)
        elif self.nvar < 20:
            return '$R' + str(self.nvar - 10)
        else:
            return '$__var{}__'.format(self.nvar)

    def is_nvar(self):
        return True

    def is_reg(self):
        return self.nvar < 20

    def is_var(self):
        return self.nvar >= 20

class LangCode(Symbol):
    def __init__(self, nlang, nsis_file):
        self.nlang = nlang
        self.nsis_file = nsis_file

    def __str__(self):
        return '$(LSTR_{})'.format(self.nlang)

    def is_lang_code(self):
        return True

class Shell(Symbol):
    def __init__(self, param1, param2):
        self.param1 = param1
        self.param2 = param2

    def __str__(self):
        ident = int.from_bytes(bytes([self.param1, self.param2]), 'little') & 0xFF
        if ident < len(SHELL_STRINGS):
            shell_string = SHELL_STRINGS[ident]
            if len(shell_string) == 0:
                return '$__SHELL_{}_{}__'.format(self.param1, self.param2)
            return '%{}%'.format(shell_string)
        return '$__SHELL_{}_{}__'.format(self.param1, self.param2)

    def is_shell(self):
        return True

class String(Symbol, bytes):
    def is_string(self):
        return True
    
    def __str__(self):
        return self.decode('utf-8')

    def __eq__(self, other):
        if isinstance(other, bytes):
            return bytes.__eq__(self, other)
        return str.__eq__(self.decode('utf-8'), other)
    
class UnicodeString(Symbol, bytes):
    def is_string(self):
        return True
    
    def __str__(self):
        return self.decode('utf-16le')

    def __eq__(self, other):
        if isinstance(other, bytes):
            return bytes.__eq__(self, other)
        return str.__eq__(self.decode('utf-16le'), other)

def _symbolize(block, offset, code_helper, is_unicode, nsis_file):
    """ Decode special characters found in NSIS strings. """
    symbols = []
    cur_string = b''
    data = bytes(block[offset:offset + fileform.NSIS_MAX_STRLEN])
    i = 0
    while i < len(data):
        c = data[i]
        c_bytes = bytes([c])
        i += 1
        if is_unicode:
            #read C as a UTF-16 character.
            c = int.from_bytes(bytes([c, data[i]]), 'little')
            c_bytes += bytes([data[i]])
            i += 1


        if c == 0:
            break

        if code_helper.is_code(c):
            if cur_string:
                if not is_unicode:
                    symbols.append(String(cur_string))
                else:
                    symbols.append(UnicodeString(cur_string))
                cur_string = b""

            param1 = data[i]
            param2 = data[i+1]
            param = ((param2 & 0x7F) << 7) | (param1 & 0x7F)

            i += 2
            if c == code_helper.NS_SHELL_CODE:
                symbols.append(Shell(param1, param2))
            elif c == code_helper.NS_VAR_CODE:
                if param == 0xFFFFFFFF:
                    symbols.append(NVar(-1))
                elif param < 20:
                    symbols.append(NVar(param))
                elif nsis_file.is_unicode and nsis_file.version_major == '2':
                    symbols.append(NVar(param & 0x7FFF))
                else:
                    symbols.append(NVar(param))
            elif c == code_helper.NS_LANG_CODE:
                used = -param+1
                if used < 0:
                    used *= -1
                    used += 1
                
                #Sometimes this has to be subtracted by 0x80.  Figure out why.
                symbols.append(LangCode(param, nsis_file)) #Im not entirely sure why this works, but it certainly seems to work.
        elif c == code_helper.NS_SKIP_CODE:
            #TODO: This can probably be removed as it doesnt make sense - see NsisIn.cpp Line 822
            cur_string += c_bytes
            i += 1
        elif c in ESCAPE_MAP:
            if not is_unicode:
                cur_string += ESCAPE_MAP[c]
            else:
                cur_string += UNICODE_ESCAPE_MAP[c]
        else:
            cur_string += c_bytes

    if cur_string:
        if not is_unicode:
            symbols.append(String(cur_string))
        else:
            symbols.append(UnicodeString(cur_string))
    return symbols, i

def symbolize(block, offset, nsis_file, version='3', is_unicode=False):
    if version == '3':
        return _symbolize(block, offset, nsis3, is_unicode, nsis_file)
    elif version == '2' and not is_unicode:
        return _symbolize(block, offset, nsis2, is_unicode, nsis_file)
    elif version == '2' and is_unicode:
        return _symbolize(block, offset, nsis2_unicode, is_unicode, nsis_file)
    else:
        raise Exception('Unknown NSIS version: ' + repr(version))

def decode(block, nsis_file, offset=0, version='3', is_unicode=False):
    symbols, i = symbolize(block, offset, nsis_file, version, is_unicode)
    string = ''
    for s in symbols:
        string += str(s)
    return string, i

