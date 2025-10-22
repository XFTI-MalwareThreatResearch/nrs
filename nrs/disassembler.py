from . import fileform, strings, method
import nrs
CF_STOP = 0x00001 #  Instruction doesn't pass execution to the next instruction
CF_CALL = 0x00002 #  CALL instruction (should make a procedure here)
CF_CHG1 = 0x00004 #  The instruction modifies the first operand
CF_CHG2 = 0x00008 #  The instruction modifies the second operand
CF_CHG3 = 0x00010 #  The instruction modifies the third operand
CF_CHG4 = 0x00020 #  The instruction modifies 4 operand
CF_CHG5 = 0x00040 #  The instruction modifies 5 operand
CF_CHG6 = 0x00080 #  The instruction modifies 6 operand
CF_USE1 = 0x00100 #  The instruction uses value of the first operand
CF_USE2 = 0x00200 #  The instruction uses value of the second operand
CF_USE3 = 0x00400 #  The instruction uses value of the third operand
CF_USE4 = 0x00800 #  The instruction uses value of the 4 operand
CF_USE5 = 0x01000 #  The instruction uses value of the 5 operand
CF_USE6 = 0x02000 #  The instruction uses value of the 6 operand
CF_JUMP = 0x04000 #  The instruction passes execution using indirect jump or call (thus needs additional analysis)
CF_SHFT = 0x08000 #  Bit-shift instruction (shl,shr...)
CF_HLL  = 0x10000 #  Instruction may be present in a high level language function.
PTR_NONE = 0xffffffff

class NsisOpcode:
    def __init__(self, name, d='', cf=0):
        self.__name = name
        self.__d = d
        self.__cf = cf

    def get_d(self):
        return self.__d
    
    def get_cf(self):
        return self.__cf
    
    def get_name(self):
        return self.__name
    
    def __str__(self):
        return self.get_name()

nsis_instructions = [
    NsisOpcode(name='INVALID'), # 0x00
    NsisOpcode(name='Return', d='', cf=CF_STOP), # 0x01
    NsisOpcode(name='Jmp', d='J', cf=CF_USE1), # 0x02
    NsisOpcode(name='Abort', d='I', cf=CF_USE1|CF_STOP), # 0x03
    NsisOpcode(name='Quit', cf=CF_STOP), #0x04
    NsisOpcode(name='Call', d='J', cf=CF_USE1|CF_CALL), # 0x05
    NsisOpcode(name='UpdateText', d='S', cf=CF_USE1), # 0x06
    NsisOpcode(name='Sleep', d='I', cf=CF_USE1), # 0x07
    NsisOpcode(name='BringToFront'), # 0x08
    NsisOpcode(name='ChDetailsView', d='SS', cf=CF_USE1|CF_USE2), # 0x09
    NsisOpcode(name='SetFileAttributes', d='SI', cf=CF_USE1|CF_USE2), # 0x0a
    NsisOpcode(name='CreateDir', d='SI', cf=CF_USE1|CF_USE2), # 0x0b
    NsisOpcode(name='IfFileExists', d='SJJ', cf=CF_USE1|CF_USE2|CF_USE3), # 0x0c
    NsisOpcode(name='SetFlag', d='IS', cf=CF_USE1|CF_USE2), # 0x0d
    NsisOpcode(name='IfFlag', d='JJII', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x0e
    NsisOpcode(name='GetFlag', d='VI', cf=CF_CHG1|CF_USE2), # 0x0f
    NsisOpcode(name='Rename', d='SSIS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x10
    NsisOpcode(name='GetFullPathName', d='SVI', cf=CF_USE1|CF_CHG2|CF_USE3), # 0x11
    NsisOpcode(name='SearchPath', d='VS', cf=CF_CHG1|CF_USE2), # 0x12
    NsisOpcode(name='GetTempFilename', d='VS', cf=CF_CHG1|CF_USE2), # 0x13
    NsisOpcode(name='ExtractFile', d='ISIIII', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_USE6), # 0x14
    NsisOpcode(name='DeleteFile', d='SI', cf=CF_USE1|CF_USE2), # 0x15
    NsisOpcode(name='MessageBox', d='ISIJIJ', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x16
    NsisOpcode(name='RmDir', d='SI', cf=CF_USE1|CF_USE2), # 0x17
    NsisOpcode(name='StrLe', d='VS', cf=CF_CHG1|CF_USE2), # 0x18
    NsisOpcode(name='StrCpy', d='VSSS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x19
    NsisOpcode(name='StrCmp', d='SSJJI', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x1a
    NsisOpcode(name='ReadEnv', d='VSI', cf=CF_CHG1|CF_USE2|CF_USE3), # 0x1b
    NsisOpcode(name='IntCmp', d='SSJJJI', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_USE6), # 0x1c
    NsisOpcode(name='IntOp', d='VSSO', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x1d
    NsisOpcode(name='IntFmt', d='VSS', cf=CF_CHG1|CF_USE2|CF_USE3), # 0x1d
    NsisOpcode(name='PushPop'), # 0x1f
    NsisOpcode(name='FindWindow', d='VSSSS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x20
    NsisOpcode(name='SendMessage', d='VSSSS2', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_USE6), # 0x21
    NsisOpcode(name='IsWindow', d='SJJ', cf=CF_USE1|CF_USE2|CF_USE3), # 0x22
    NsisOpcode(name='GetDlgItem', d='VSS', cf=CF_CHG1|CF_USE2|CF_USE3), # 0x23
    NsisOpcode(name='SetCtlColors', d='SI', cf=CF_USE1|CF_USE2), # 0x24
    NsisOpcode(name='SetBrandingImage', d='SII', cf=CF_USE1|CF_USE2), # 0x25
    NsisOpcode(name='CreateFont', d='VSSSI', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x26
    NsisOpcode(name='ShowWindow', d='SS', cf=CF_USE1|CF_USE2), # 0x27
    NsisOpcode(name='ShellExec', d='SSSS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x28
    NsisOpcode(name='Execute', d='SII', cf=CF_USE1|CF_USE2|CF_USE3), # 0x29
    NsisOpcode(name='GetFileTime', d='VVS', cf=CF_CHG1|CF_CHG2|CF_USE3), # 0x2a
    NsisOpcode(name='GetDLLVersion', d='VVS', cf=CF_CHG1|CF_CHG2|CF_USE3), # 0x2b
    NsisOpcode(name='RegisterDLL', d='SSSI', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x2c
    NsisOpcode(name='CreateShortcut', d='SSSSS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x2d
    NsisOpcode(name='CopyFiles', d='SSS', cf=CF_USE1|CF_USE2|CF_USE3), # 0x2e
    NsisOpcode(name='Reboot'), # 0x2f
    NsisOpcode(name='WriteIni', d='SSSS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x30
    NsisOpcode(name='ReadIni', d='VSSS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x31
    NsisOpcode(name='DeleteRegKey', d='ISSS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x32
    NsisOpcode(name='WriteRegValue', d='ISSII', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x33
    NsisOpcode(name='ReadRegValue', d='VISSI', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x34
    NsisOpcode(name='RegEnumKey', d='VISS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x35
    NsisOpcode(name='FileClose', d='V', cf=CF_USE1), # 0x36
    NsisOpcode(name='FileOpen', d='VIIS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x37
    NsisOpcode(name='FileWrite', d='VS', cf=CF_USE1|CF_USE2), # 0x38
    NsisOpcode(name='FileRead', d='VVS', cf=CF_USE1|CF_CHG2|CF_USE3), # 0x39
    NsisOpcode(name='FileSeek', d='VVSI', cf=CF_USE1|CF_CHG2|CF_USE3|CF_USE4), # 0x3a
    NsisOpcode(name='FindClose', d='V', cf=CF_USE1), # 0x3b
    NsisOpcode(name='FindNext', d='VV', cf=CF_CHG1|CF_USE2), # 0x3c
    NsisOpcode(name='FindFirst', d='VVS', cf=CF_CHG1|CF_CHG2|CF_USE3), # 0x3d
    NsisOpcode(name='WriteUninstaller', d='SIIS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x3e
    NsisOpcode(name='LogText', d='S', cf=CF_USE1), # 0x3f
    NsisOpcode(name='SectionSet', d='SII', cf=CF_USE1|CF_USE2|CF_USE3), # 0x40
    NsisOpcode(name='InstTypeSet', d='SIII', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x41
    NsisOpcode(name='GetLabelAddr'), # 0x42
    NsisOpcode(name='GetFunctionAddr'), # 0x43
    NsisOpcode(name='LockWindow', d='I', cf=CF_USE1), # 0x44
    NsisOpcode(name='Push', d='S', cf=CF_USE1), #0x45
    NsisOpcode(name='Pop', d='V', cf=CF_CHG1), # 0x46
    NsisOpcode(name='Exch', d='I', cf=CF_USE1|CF_CHG1), # 0x47
    NsisOpcode(name='ClearErrors'), # 0x48
    NsisOpcode(name='IfErrors', d='J', cf=CF_USE1), # 0x49
    NsisOpcode(name='AssignVar', d='VS', cf=CF_CHG1|CF_USE2), # 0x4A
    NsisOpcode(name='EnableWindow', d='SS', cf=CF_USE1|CF_USE2), # 0x4B
    NsisOpcode(name='HideWindow', d='SS', cf=CF_USE1|CF_USE2), # 0x4C
    NsisOpcode(name='DeleteRegValue', d='ISSS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), #0x4D
    NsisOpcode(name='RegEnumValue', d='VISS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x4E
    NsisOpcode(name='FileWriteByte', d='VS', cf=CF_USE1|CF_USE2), # 0x4F
    NsisOpcode(name='FileReadByte', d='VV', cf=CF_USE1|CF_CHG2), # 0x50
    NsisOpcode(name='LogSet', d='I', cf=CF_USE1), # 0x51
    NsisOpcode(name='PluginCall', cf=CF_USE1|CF_USE2|CF_USE3), # 0x52
    NsisOpcode(name='GetFontVersion', d='V', cf=CF_USE1), #0x53
    NsisOpcode(name='GetFontName', d='V', cf=CF_USE1), # 0x54
    NsisOpcode(name='FindProc', d='V', cf=CF_USE1) # 0x55
]

class NsisInstruction:
    def __init__(self, nsis_file, nsis_opcode, operands, offset, method_start_offset):
        self.__nsis_file = nsis_file
        self.__nsis_opcode = nsis_opcode
        self.__operands = list()
        self.__raw_operands = list(operands)
        self.__offset = offset
        for x in range(len(operands)):
            d = self.__nsis_opcode.get_d()
            if x >= len(d):
                break
            format_ident = d[x]
            initial_value = operands[x]
            if format_ident == 'I' or (format_ident == 'J' and initial_value <= 0) or format_ident == 'O':
                self.__operands.append(initial_value)
            else:
                if format_ident == 'S':
                    self.__operands.append(self.__nsis_file.get_string(initial_value))
                elif format_ident == 'V':
                    if initial_value < 20:
                        self.__operands.append(strings.NVar(initial_value))
                    elif initial_value == 0xffffffff: #TODO: Figure out what the deal is with this -1 case.
                        self.__operands.append(-1)
                    else:
                        if self.__nsis_file.version_major == '2' and self.__nsis_file.is_unicode:
                            self.__operands.append(strings.NVar(initial_value & 0x7FFF))
                        else:
                            self.__operands.append(strings.NVar(initial_value))
                elif format_ident == 'J':
                    method_offset = nrs.entry_to_offset(initial_value - 1)
                    if self.__nsis_opcode.get_name() == 'Call':
                        if nsis_file.get_method_by_offset(method_offset) == None:
                            nsis_file.methods[method_offset] = method.NsisMethod(nsis_file, None, method_offset)
                        self.__operands.append(nsis_file.get_method_by_offset(method_offset))
                    else:
                        method_obj = self.__nsis_file.get_method_by_offset(method_start_offset)
                        if method_obj != None:
                            method_obj.add_label(method_offset)
                        self.__operands.append(strings.Label(method_offset))
                elif format_ident == '2':
                    self.__operands.append(initial_value >> 2)
                else:
                    raise Exception('Unknown format flag.')
                
    def get_name(self):
        return self.get_opcode().get_name()

    def get_opcode(self):
        return self.__nsis_opcode
    
    def get_nsis_file(self):
        return self.__nsis_file
    
    def get_operands(self):
        return self.__operands

    def get_raw_operands(self):
        return self.__raw_operands
    
    def get_offset(self):
        return self.__offset
    
    def __str__(self):
        string_val = ''
        string_val += str(self.__nsis_opcode)
        if len(self.__operands) > 0:
            string_val += ' '
        for x in range(len(self.__operands)):
            operand = self.__operands[x]
            if isinstance(operand, int):
                string_val += hex(operand)
            else:
                if isinstance(operand, strings.UnicodeString) or isinstance(operand, strings.String) or isinstance(operand, str):
                    string_val += '\"{}\"'.format(str(operand))
                elif isinstance(operand, strings.NVar):
                    string_val += str(operand)
                else:
                    string_val += str(operand)
            
            if x != len(self.__operands) - 1:
                string_val += ', '
        return string_val

class NsisDisassembler:
    def __init__(self, nsis_file, method_offset, method_end):
        self.__nsis_file = nsis_file
        self.__method_offset = method_offset #base this offset off of NB_ENTRIES offset.
        self.__instructions = list()
        self.__method_end = method_end
        self.__disassemble()

    def __handle_virt_instruction(self, opcode, params):
        if opcode.get_name() == 'PushPop':
            if params[1]:
                return nsis_instructions[0x46] #Pop
            elif params[2]:
                return nsis_instructions[0x47] #Exch
            else:
                return nsis_instructions[0x45] #Push
        elif opcode.get_name() == 'SetFlag':
            if params[0] == 2 and params[1] == 0xAC:
                return nsis_instructions[0x48] #ClearErrors
        elif opcode.get_name() == 'IfFlag':
            if params[1] == 0 and params[2] == 2 and params[3] == 0:
                return nsis_instructions[0x49] #IfErrors
        elif opcode.get_name() == 'StrCpy':
            if params[2] == 0 and params[3] == 0:
                return nsis_instructions[0x4A] #AssignVar
        elif opcode.get_name() == 'ShowWindow':
            if params[2]:
                return nsis_instructions[0x4C] #HideWindow
            elif params[3]:
                return nsis_instructions[0x4B] #EnableWindow
        elif opcode.get_name() == 'DelReg':
            if params[4]:
                return nsis_instructions[0x32] #DeleteRegKey
            return nsis_instructions[0x4D] #DeleteRegValue
        elif opcode.get_name() == 'RegEnum':
            if params[4]:
                return nsis_instructions[0x35] #RegEnumKey
            return nsis_instructions[0x4E] #RegEnumValue
        elif opcode.get_name() == 'FileWrite':
            if params[2]:
                return nsis_instructions[0x4F] #FileWriteByte
        elif opcode.get_name() == 'FileRead':
            if params[3]:
                return nsis_instructions[0x50] #FileReadByte
        elif opcode.get_name() == 'LogText':
            if params[0]:
                return nsis_instructions[0x51] #LogSet
            return nsis_instructions[0x3F] #LogText
        return opcode
    
    def is_park(self):
        return self.__nsis_file.is_unicode and self.__nsis_file.version_major == '2'
    
    def is_park1(self):
        if not self.is_park():
            return False
        
        #for park files langtable num 0 should be version string.
        ver_string = str(self.__nsis_file.get_langtable_strings()[0])
        if not ver_string.startswith('Nullsoft Install System (Unicode) v'):
            raise Exception('Invalid version string while detecting Park version.')
        ver_string = ver_string.lstrip('Nullsoft Install System (Unicode) v')
        ver_string = ver_string.split('-')[0]
        ver_args = ver_string.split('.')
        if int(ver_args[1]) <= 46 and int(ver_args[2]) <= 1:
            return True
        return False

    def is_park2(self):
        if not self.is_park():
            return False
        #for park files langtable num 0 should be version string.
        ver_string = str(self.__nsis_file.get_langtable_strings()[0])
        if not ver_string.startswith('Nullsoft Install System (Unicode) v'):
            raise Exception('Invalid version string while detecting Park version.')
        ver_string = ver_string.lstrip('Nullsoft Install System (Unicode) v')
        ver_string = ver_string.split('-')[0]
        ver_args = ver_string.split('.')
        if int(ver_args[1]) == 46 and int(ver_args[2]) == 2:
            return True
        return False

    def is_park3(self):
        if not self.is_park():
            return False
        #for park files langtable num 0 should be version string.
        ver_string = str(self.__nsis_file.get_langtable_strings()[0])
        if not ver_string.startswith('Nullsoft Install System (Unicode) v'):
            raise Exception('Invalid version string while detecting Park version.')
        ver_string = ver_string.lstrip('Nullsoft Install System (Unicode) v')
        ver_string = ver_string.split('-')[0]
        ver_args = ver_string.split('.')
        if int(ver_args[1]) >= 46 and int(ver_args[2]) >= 3:
            return True
        return False
    
    def is_unicode(self):
        return self.__nsis_file.is_unicode
    
    def __translate_cmd(self, opval):
        if not self.is_park():
            return opval #For sake of simplicity lets assume log command is not enabled on non Park files.  May want to eventually work on detection depending on if anythings weird though.
            
        if opval < 44:
            return opval
        
        if self.is_park2() or self.is_park3():
            if opval == 44:
                return 0x53 #EW_GETFONTVERSION - we may not support this opcode yet.
            opval -= 1
        if self.is_park3():
            if opval == 44:
                return 0x54 #EW_GETFONTNAME - not supported yet
            opval -= 1
        if opval >= 58:
            if self.is_unicode():
                if opval == 58:
                    return 0x38 #EW_FPUTWS
                if opval == 59:
                    return 0x39 #EW_FGETWS
                opval -= 2
            if opval >= 63 and self.is_park3():
                if opval == 63:
                    return 0x51 #EW_LOG
                return opval - 1
            if opval == 68:
                return 0x55 #EW_FINDPROC
        return opval

    def __disassemble(self):
        entries_block = self.__nsis_file.block(fileform.NB_ENTRIES)
        current_offset = self.__method_offset
        while current_offset < len(entries_block):
            if self.__method_end != -1:
                if current_offset >= self.__method_end:
                    break
            instr_offset = current_offset
            opcode_num = int.from_bytes(entries_block[current_offset:current_offset+4], 'little')
            opcode_num = self.__translate_cmd(opcode_num)
            current_offset += 4
            if opcode_num >= len(nsis_instructions):
                opcode_obj = nsis_instructions[0] #INVALID - should throw errors?
            else:
                opcode_obj = nsis_instructions[opcode_num]
            operands = list()
            for _ in range(6):
                operands.append(int.from_bytes(entries_block[current_offset:current_offset+4], 'little'))
                current_offset += 4
            opcode_obj = self.__handle_virt_instruction(opcode_obj, operands)
            instr_obj = NsisInstruction(self.__nsis_file, opcode_obj, operands, instr_offset, self.__method_offset)
            self.__instructions.append(instr_obj)

    def get_instructions(self):
        return self.__instructions