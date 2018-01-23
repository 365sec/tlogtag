
class LogIdentify:
    
    def __init__(self):
        print "LogIdentify log"
        self._MAX_LINE_LEN = 1024
        
    def check(self,plugin,line):
        rules = plugin.get_plugin_rules()
        for rule in rules:
            rule.feed(line)
            if rule.match():
                rule.generate_event()
                print('Match rule: [%s] -> %s' % (rule.name, line))
                return True
            
        return False
        

    def identify_line(self,plugins,line):
        for plugin in plugins :
            if self.check(plugin,line):
                return plugin
        return None
    
    def idendtify_logfile(self,plugins,path):
        f = open(path,'rb') 
        line  = f.readline()
        f.close()
        print len(line)
        if len(line) > self._MAX_LINE_LEN :
            return None
        return self.identify_line(plugins,line)
        
        
        