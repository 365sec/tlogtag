import re

class ApacheLog:
    
    def __init__(self):
        print "---"
        self.regex_flags = re.IGNORECASE | re.UNICODE
        self.rules =[{"name":"apache-access",
          "pattern":re.compile("""((?P<dst>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<port>\d{1,5}))? )?(?P<src>\S+) (?P<id>\S+) (?P<user>\S+) \[(?P<date>\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})\s+[+-]\d{4}\] \"(?P<request>[^\"]*)\" (?P<code>\d{3}) ((?P<size>\d+)|-)( \"(?P<referer_uri>[^\"]*)\" \"(?P<useragent>[^\"]*)\")?$""", self.regex_flags),
        },{
            "name":"apache-access",
            "pattern":re.compile("""\[(?P<date>\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4})\] \[(?P<type>(emerg|alert|crit|error|warn|notice|info|debug))\] (\[client (?P<src>\S+)\] )?(?P<data>.*)""", self.regex_flags)
        }]
        
        self.text = """183.171.88.167 - - [02/Jan/2018:20:54:15 -0800] "GET /tablefilter.js HTTP/1.1" 200 6670"""
       
        
    
    def check(self,line):
        for rule in self.rules:
           pattern = rule["pattern"]
           result = pattern.search(line)
           
           if result:
               return True
        
        return False
    
                  
    def collect(self,line):
        for rule in self.rules:
           pattern = rule["pattern"]
           result = pattern.search(line)
           if result:
               groups  = result.groupdict()
               print groups
               for key, group in groups.iteritems():
                 if group is None:
                     group = ''
                     value = ''
                     value = str(group.encode('utf-8'))
                     print key,group
                     print rule
                 else :
                  print key,group
                  

if __name__ == "__main__":
    al = ApacheLog()
    print al.check(al.text)