import re


class Tlogtag:
    
    def __init__(self):
        print "__init__"

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
    
    
    def apache_log(self):
        regexp = """((?P<dst>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<port>\d{1,5}))? )?(?P<src>\S+) (?P<id>\S+) (?P<user>\S+) \[(?P<date>\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})\s+[+-]\d{4}\] \"(?P<request>[^\"]*)\" (?P<code>\d{3}) ((?P<size>\d+)|-)( \"(?P<referer_uri>[^\"]*)\" \"(?P<useragent>[^\"]*)\")?$"""
        text = """183.171.88.167 - - [02/Jan/2018:20:54:15 -0800] "GET /tablefilter.js HTTP/1.1" 200 6670"""
        print regexp
        
        #regexp = self.rule['regexp']
        regex_flags = re.IGNORECASE | re.UNICODE
        pattern = re.compile(regexp, regex_flags)
        result = pattern.search(text)
        groups  = result.groupdict()
        print groups
        for key, group in groups.iteritems():
            if group is None:
                group = ''
                value = ''
                value = str(group.encode('utf-8'))
                print key,group
        
        print "+++"


if __name__ == "__main__":
    tlog = Tlogtag()
    tlog.apache_log()