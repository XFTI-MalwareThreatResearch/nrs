# Strings escape characters.
NS_SKIP_CODE = 0xE000
NS_VAR_CODE = 0xE001
NS_SHELL_CODE = 0xE002
NS_LANG_CODE = 0xE003

def is_code(c):
    return c & NS_SKIP_CODE != 0

