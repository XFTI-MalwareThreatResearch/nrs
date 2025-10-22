class NsisMethod:
    def __init__(self, nsis_file, method_name, method_offset):
        self.__nsis_file = nsis_file
        self.__method_name = method_name
        self.__method_offset = method_offset
        self.__method_end = -1
        self.__labels = list()
        if self.__method_name == None:
            self.__method_name = 'sub_{}'.format(hex(method_offset))

    def set_method_end(self, method_end):
        self.__method_end = method_end

    def get_method_end(self):
        if self.__method_end == -1:
            raise Exception('Method end has not been initialized')
        return self.__method_end

    def get_nsis_file(self):
        return self.__nsis_file
    
    def get_name(self):
        return self.__method_name
    
    def get_method_offset(self):
        return self.__method_offset

    def __str__(self):
        return self.__method_name

    def get_labels(self):
        return self.__labels

    def add_label(self, offset):
        if offset not in self.__labels:
            self.__labels.append(offset)