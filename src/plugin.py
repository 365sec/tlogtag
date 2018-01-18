import re
import ParserUtil
from Config import Conf,split_variables
from pluginrule import RuleMatch

class Plugin(Conf):
    _NEEDED_CONFIG_ENTRIES = {'config': ['type', 'source', 'enable']}
    _EXIT_IF_MALFORMED_CONFIG = False
    TRANSLATION_SECTION = 'translation'
    TRANSLATION_FUNCTION = 'translate'
    TRANSLATION_DEFAULT = '_DEFAULT_'
    SECTIONS_NOT_RULES = ['config', 'info', TRANSLATION_SECTION]
    CONCAT_FUNCTION = 'CONCAT'
    _MAP_REPLACE_VARIABLE = 1
    _MAP_REPLACE_TRANSLATIONS = 4
    _MAP_REPLACE_USER_FUNCTIONS = 8
    _MAP_REPLACE_CUSTOM_USER_FUNCTIONS = 16
    _MAP_REPLACE_CONCAT = 32
    _MAP_REPLACE_TRANSLATE2 = 64
    __parserUtilFunctionsLoaded = False
    __parserUtilFunctions = {}
    __regexReplArrayVariables = re.compile('\\{\\$[^\\}\\{]+\\}', re.UNICODE)
    __regexReplCustomUserFunctionArray = re.compile('(\\{:(\\w+)\\((\\$[^\\)]+)?\\)\\})', re.UNICODE)
    __regexReplUserArrayFunctions = re.compile('(\\{(\\w+)\\((\\$[^\\)]+)\\)\\})', re.UNICODE)
    __regexReplVariables = re.compile('\\{\\$[^\\}\\{]+\\}', re.UNICODE)
    __regexTranslationSection = re.compile('(\\{(' + TRANSLATION_FUNCTION + ')\\(\\$([^\\)]+)\\)\\})', re.UNICODE)
    __regexReplUserFunctions = re.compile('(\\{(\\w+)\\((\\$[^\\)]+)\\)\\})', re.UNICODE)
    __regexReplCustomUserFunctions = re.compile('(\\{:(\\w+)\\((\\$[^\\)]+)?\\)\\})', re.UNICODE)
    __regexReplConcatFunction = re.compile('\\$CONCAT\\((?P<params>.*)\\)', re.UNICODE)
    __regex_check_for_translate2_function = re.compile('\\{translate2\\((?P<variable>\\$[^\\)]+),(?P<translate_section>\\$[^\\)]+)\\)\\}', re.UNICODE)
    __regexIsTranslationSection = re.compile('translation-\\S+', re.UNICODE)
    __CUSTOM_TRANSLATION_SECTIONS = {}


    def get_plugin_rules(self):
        rules = []
        unsorted_rules = self.rules()
        keys = unsorted_rules.keys()
        keys.sort()
        for key in keys:
            item = unsorted_rules[key]
            if 'regexp' in item:
                rules.append(RuleMatch(key, item, self))
            else:
              print('Cannot load rule %s without regular expression' % key)
    
        return rules


    def rules(self):
        rules = {}
        for section in sorted(self.sections()):
            regexp = self.get(section, 'regexp')
            if self.get('config', 'source') == 'log' and (regexp is None or regexp == ''):
                continue
            if Plugin.__regexIsTranslationSection.match(section.lower()) is not None:
                if section.lower() not in Plugin.SECTIONS_NOT_RULES:
                    print('Loading new translation section... %s' % section.lower())
                    Plugin.SECTIONS_NOT_RULES.append(section.lower())
            if section.lower() not in Plugin.SECTIONS_NOT_RULES:
                rules[section] = self.hitems(section, True)

        return rules

    def _replace_array_variables(self, value, groups):
        rvalue = None
        for i in range(2):
            search = self.__regexReplArrayVariables.findall(value)
            rvalue = value
            if search:
                for string in search:
                    var = string[2:-1]
                    try:
                        var_position = int(var)
                        if var_position < len(groups):
                            rvalue = rvalue.replace(string, str(groups[var_position]))
                    except ValueError:
                        rvalue = value

        return rvalue

    def get_replace_array_value(self, value, groups):
        rvalue = self._replace_array_variables(value, groups)
        if rvalue == value:
            rvalue = self._replace_user_array_functions(value, groups)
        if rvalue == value:
            rvalue = self._replace_custom_user_function_array(value, groups)
        return rvalue

    def _replace_custom_user_function_array(self, value, groups):
        search = self.__regexReplCustomUserFunctionArray.findall(value)
        if search:
            for string in search:
                string_matched, func, variables = string
                vars = split_variables(variables)
                for var in vars:
                    try:
                        var_pos = int(var)
                    except TypeError:
                        return value

                    if var_pos >= len(groups):
                        return value

                func_name = '%s_%s' % (func, self.get('DEFAULT', 'plugin_id'))
                if func_name != Plugin.TRANSLATION_FUNCTION and hasattr(Plugin, func_name):
                    f = getattr(Plugin, func_name)
                    args = [self]
                    for i in range(len(vars)):
                        args.append(str(groups[int(vars[i])]))

                    try:
                        a = str(f(*args))
                        value = value.replace(string_matched, a)
                    except TypeError as e:
                        print(str(e))

                else:
                    value = value.replace(string_matched, str(groups[var]))

        return value

    def _replace_user_array_functions(self, value, groups):
        if value is None:
            return
        else:
            search = self.__regexReplUserArrayFunctions.findall(value)
            if search:
                for string in search:
                    string_matched, func, variables = string
                    vars = split_variables(variables)
                    for var in vars:
                        if len(groups) - 1 < int(var):
                            return value

                    if func != Plugin.TRANSLATION_FUNCTION and hasattr(ParserUtil, func):
                        f = getattr(ParserUtil, func)
                        args = []
                        for i in range(len(vars)):
                            args.append(str(groups[int(vars[i])]))

                        try:
                            a = f(*args)
                            value = value.replace(string_matched, a)
                        except TypeError as e:
                            print(str(e))

                    else:
                        for v in vars:
                            if int(v) > len(groups) - 1:
                                print('Error var:%d, is greatter than groups size. (%d)' % (int(v), len(groups)))
                            else:
                                var_value = groups[int(v)]
                                if self.has_section(Plugin.TRANSLATION_SECTION):
                                    if self.has_option(Plugin.TRANSLATION_SECTION, var_value):
                                        value = self.get(Plugin.TRANSLATION_SECTION, var_value)

            return value

    def replace_config(self, conf):
        for section in sorted(self.sections()):
            for option in self.options(section):
                regexp = self.get(section, option)
                search = re.findall('(\\\\_CFG\\(([\\w-]+),([\\w-]+)\\))', regexp, re.UNICODE)
                if search:
                    for string in search:
                        all, arg1, arg2 = string
                        if conf.has_option(arg1, arg2):
                            value = conf.get(arg1, arg2)
                            regexp = regexp.replace(all, value)
                            self.set(section, option, regexp)

    def replace_aliases(self, aliases):
        plugin_rules = self.rules()
        for rulename, rule in plugin_rules.iteritems():
            if 'regexp' not in rule:
                print('Invalid rule: %s' % rulename)
                continue
            regexp = rule['regexp']
            search = re.findall('\\\\\\w\\w+', regexp, re.UNICODE)
            if search:
                for string in search:
                    repl = string[1:]
                    if aliases.has_option('regexp', repl):
                        value = aliases.get('regexp', repl)
                        regexp = regexp.replace(string, value)
                        self.set(rulename, 'regexp', regexp)

    def _replace_variables(self, value, groups, rounds = 2):
        for i in range(rounds):
            search = self.__regexReplVariables.findall(value)
            if search:
                for string in search:
                    var = string[2:-1]
                    if groups.has_key(var):
                        value = value.replace(string, str(groups[var]))

        return value

    def _replace_variables_assess(self, value):
        ret = 0
        search = re.findall('\\{\\$[^\\}\\{]+\\}', value, re.UNICODE)
        if search:
            ret = self._MAP_REPLACE_VARIABLE
        return ret

    def _replace_translations(self, value, groups):
        search = self.__regexTranslationSection.findall(value)
        if search:
            for string in search:
                string_matched, func, var = string
                try:
                    if self.has_section(Plugin.TRANSLATION_SECTION):
                        if self.has_option(Plugin.TRANSLATION_SECTION, groups[var]):
                            value = self.get(Plugin.TRANSLATION_SECTION, groups[var])
                        elif self.has_option(Plugin.TRANSLATION_SECTION, Plugin.TRANSLATION_DEFAULT):
                            value = self.get(Plugin.TRANSLATION_SECTION, Plugin.TRANSLATION_DEFAULT)
                        else:
                            value = groups[var]
                    else:
                        value = groups[var]
                except:
                    pass

        return value

    def _replace_translations_assess(self, value):
        regexp = '(\\{(' + Plugin.TRANSLATION_FUNCTION + ')\\(\\$([^\\)]+)\\)\\})'
        search = re.findall(regexp, value, re.UNICODE)
        if search:
            return self._MAP_REPLACE_TRANSLATIONS
        return 0

    def __loadParserUtilFunctions(self):
        self.__parserUtilFunctionsLoaded = True
        attrlist = dir(ParserUtil)
        for attr in attrlist:
            f = getattr(ParserUtil, attr)
            self.__parserUtilFunctions[attr] = f

    def _replace_user_functions(self, value, groups):
        if not self.__parserUtilFunctionsLoaded:
            self.__loadParserUtilFunctions()
        search = self.__regexReplUserFunctions.findall(value)
        if search:
            for string in search:
                string_matched, func, variables = string
                vars = split_variables(variables)
                for var in vars:
                    if not groups.has_key(var):
                        return value

                if func != Plugin.TRANSLATION_FUNCTION and self.__parserUtilFunctions.has_key(func):
                    f = self.__parserUtilFunctions[func]
                    args = []
                    for i in range(len(vars)):
                        args.append(str(groups[vars[i]]))

                    args.append(id(self))
                    try:
                        a = f(*args)
                        value = value.replace(string_matched, str(a))
                    except Exception as err:
                        print("Error calling func with args '%s' ->  %s" % (args, str(err)))

                else:
                    value = value.replace(string_matched, str(groups[var]))

        return value

    def _replace_user_functions_assess(self, value):
        search = re.findall('(\\{(\\w+)\\((\\$[^\\)]+)\\)\\})', value, re.UNICODE)
        if search:
            return self._MAP_REPLACE_USER_FUNCTIONS
        return 0

    def _replace_custom_user_functions_assess(self, value):
        search = re.findall('(\\{:(\\w+)\\((\\$[^\\)]+)?\\)\\})', value, re.UNICODE)
        if search:
            return self._MAP_REPLACE_CUSTOM_USER_FUNCTIONS
        return 0

    def _replace_custom_user_functions(self, value, groups):
        search = self.__regexReplCustomUserFunctions.findall(value)
        if search:
            for string in search:
                string_matched, func, variables = string
                vars = split_variables(variables)
                for var in vars:
                    if not groups.has_key(var):
                        return value

                func_name = '%s_%s' % (func, self.get('DEFAULT', 'plugin_id'))
                if func_name != Plugin.TRANSLATION_FUNCTION and hasattr(Plugin, func_name):
                    f = getattr(Plugin, func_name)
                    args = [self]
                    for i in range(len(vars)):
                        args.append(str(groups[vars[i]]))

                    try:
                        a = str(f(*args))
                        value = value.replace(string_matched, a)
                    except TypeError as e:
                        print(str(e))

                else:
                    value = value.replace(string_matched, str(groups[var]))

        return value

    def __replaceConcatFunction(self, value, groups):
        concat = ''
        m = self.__regexReplConcatFunction.match(value)
        if m:
            mdict = m.groupdict()
            if mdict.has_key('params'):
                paramlist = mdict['params'].split(',')
                for param in paramlist:
                    if param.startswith('$'):
                        if groups.has_key(param[1:]):
                            concat += groups[param[1:]]
                        else:
                            concat += param
                    else:
                        concat += param

        return concat

    def __checkReplaceConcatFunction(self, value):
        ret = 0
        if re.match('\\$CONCAT\\((.*)\\)', value):
            ret = self._MAP_REPLACE_CONCAT
        return ret

    def __replace_translate2_function(self, value, groups):
        m = self.__regex_check_for_translate2_function.match(value)
        if m:
            mdict = m.groupdict()
            if 'variable' in mdict and 'translate_section' in mdict:
                variable = mdict['variable'].replace('$', '')
                translate_section = mdict['translate_section'].replace('$', '')
                if variable in groups:
                    if self.has_section(translate_section):
                        if self.has_option(translate_section, groups[variable]):
                            replaced_value = self.get(translate_section, groups[variable])
                            return replaced_value
                        print('Translate2 variable(%s) not found on the translate section %s' % (groups[variable], translate_section))
                    else:
                        print('Translate2 translation_section(%s) not found' % translate_section)
        replaced_value = value
        return replaced_value

    def __check_for_translate2_function(self, value):
        ret = 0
        if Plugin.__regex_check_for_translate2_function.match(value) is not None:
            ret = self._MAP_REPLACE_TRANSLATE2
        return ret

    def replace_value_assess(self, value):
        ret = self._replace_variables_assess(value)
        ret |= self._replace_translations_assess(value)
        ret |= self._replace_user_functions_assess(value)
        ret |= self._replace_custom_user_functions_assess(value)
        ret |= self.__checkReplaceConcatFunction(value)
        ret |= self.__check_for_translate2_function(value)
        return ret

    def get_replace_value(self, value, groups, replace = 15):
        if replace > 0:
            if replace & self._MAP_REPLACE_VARIABLE:
                value = self._replace_variables(value, groups, replace & self._MAP_REPLACE_VARIABLE)
            if replace & self._MAP_REPLACE_TRANSLATIONS:
                value = self._replace_translations(value, groups)
            if replace & self._MAP_REPLACE_USER_FUNCTIONS:
                value = self._replace_user_functions(value, groups)
            if replace & self._MAP_REPLACE_CUSTOM_USER_FUNCTIONS:
                value = self._replace_custom_user_functions(value, groups)
            if replace & self._MAP_REPLACE_CONCAT:
                value = self.__replaceConcatFunction(value, groups)
            if replace & self._MAP_REPLACE_TRANSLATE2:
                value = self.__replace_translate2_function(value, groups)
        return value

    def setUnicode(self):
        self.__UTF8_ENCODED = True

    def isUnicode(self):
        return self.__UTF8_ENCODED