from nrs import fileform, strings

class NsiFileDumper:
    def __init__(self, nsis_file):
        self.__nsis_file = nsis_file
        self.__buffer: str = ''

    def write_line(self, line, indent=0):
        self.__buffer += ((' ' * 4) * indent) + line + '\n'

    def do_first_info_lines(self):
        if self.__nsis_file.is_unicode:
            self.write_line('; NSIS script (UTF-8) NSIS-{} (Unicode)'.format(self.__nsis_file.version_major))
        else:
            self.write_line('; NSIS script (UTF-8) NSIS-{} (ASCII)'.format(self.__nsis_file.version_major))
        self.write_line('')
        if self.__nsis_file.is_unicode:
            self.write_line('Unicode true')
        else:
            self.write_line('Unicode false')
        if self.__nsis_file.compressor == '':
            self.__nsis_file.compressor = 'unknown'
        self.write_line('SetCompressor {}'.format(self.__nsis_file.compressor))
        self.write_line('')
        self.write_line('')
    
    def do_langtable(self):
        #Name is 2nd langstring
        #brandingtext is 0th langstring
        lang_strings = self.__nsis_file.get_langtable_strings()
        if lang_strings[2] != '':
            self.write_line('Name {}'.format(lang_strings[2]))
        if lang_strings[0] != '':
            self.write_line('BrandingText {}'.format(lang_strings[0]))

        self.write_line('')
        lang_table = self.__nsis_file.get_langtable_strings()
        lang_id = self.__nsis_file.get_langtable_lang_id()
        for x in range(len(lang_table)):
            self.write_line('LangString LSTR_{} {} \"{}\"'.format(x, hex(lang_id).lstrip('0x'), lang_table[x]))
        
        self.write_line('')
        self.write_line('')

    def count_num_vars(self):
        max_var = 0 #first 20 count should be reg.
        for method_obj in self.__nsis_file.methods.values():
            disasm = self.__nsis_file.disassemble_method(method_obj)
            for instr in disasm.get_instructions():
                usable_operands_size = len(instr.get_operands())
                for x in range(usable_operands_size):
                    original_operand = instr.get_operands()[x]
                    if not isinstance(original_operand, int):
                        if isinstance(original_operand, strings.UnicodeString) or isinstance(original_operand, strings.String):
                            symbols, i = strings.symbolize(self.__nsis_file.block(fileform.NB_STRINGS), self.get_raw_operands()[x], self.__nsis_file, self.__nsis_file.version_major, self.__nsis_file.is_unicode) #symbolize(block, offset, nsis_file, version='3', is_unicode=False)
                            for sym in symbols:
                                if isinstance(sym, strings.NVar):
                                    if sym.nvar > max_var and not sym.is_reg():
                                        max_var = sym.nvar
                        elif isinstance(original_operand, strings.NVar):
                            if original_operand.nvar > max_var and not original_operand.is_reg():
                                max_var = original_operand.nvar
        return max_var

    def do_vars(self):
        #TODO: figure out how I want to do variables.
        #Likely going to have to count up all of the ones used in the code.
        amt_vars = self.count_num_vars()
        for x in range(amt_vars):
            self.write_line('Var __var{}__'.format(x))
        self.write_line('')
        self.write_line('')

    def do_installer_vars(self):
        #self.write_line('')
        #self.write_line('')
        pass #This is in the 7-Zip one but doesnt really seem useful.  May add later.

    def do_pages(self):
        #TODO: figure out how to do pages
        #self.write_line('')
        #self.write_line('')
        pass #same as do_installer_vars()

    def do_methods(self):
        for method_obj in self.__nsis_file.methods.values():
            self.write_line('Function {}'.format(method_obj.get_name()))
            disasm_obj = self.__nsis_file.disassemble_method(method_obj)
            for instr in disasm_obj.get_instructions():
                if instr.get_offset() in method_obj.get_labels():
                    self.write_line('label_{}:'.format(hex(instr.get_offset()).lstrip('0x')))
                self.write_line(str(instr), indent=1)
            self.write_line('FunctionEnd')
            self.write_line('')
            self.write_line('')

    def process(self):
        self.do_first_info_lines()
        self.do_langtable()
        self.do_vars()
        self.do_installer_vars()
        self.do_pages()
        self.do_methods()
        return self.__buffer