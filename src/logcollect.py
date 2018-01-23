import os
from  identify  import LogIdentify


class Logcollect :
    def __init__(self,plugins):
        print "++init++"
        
        self.__logidentify = LogIdentify()
        self.__plugins = plugins
    
    
    def collect(self,plugin,line):
        rules = plugin.get_plugin_rules()
        for rule in rules:
            rule.feed(line)
            if rule.match():
                rule.generate_event()
                print('Match rule: [%s] -> %s' % (rule.name, line))
                return True
            
        return False
     
        
    def collect_file(self,file):
        print file
        plugin = self.__logidentify.idendtify_logfile(self.__plugins, file)
        if plugin :
            print "collect---------"
            f = open(file,'rb') 
            for line in f:
              self.collect(plugin, line)
            f.close() 
        
    
    
    
    def collect_dir(self,path):  
        for root ,dirs,files in os.walk(path):
            for file in files:
               if os.path.splitext(file)[1] == '.log' or os.path.splitext(file)[1] == '.txt':
                   self.collect_file(os.path.join(root,file))
            for dir in dirs:
                self.collect_dir(dir)