# -*- coding:utf-8 -*-

import os
from  identify  import LogIdentify
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import uuid


client = Elasticsearch(hosts=["172.16.39.231","172.16.39.232","172.16.39.233","172.16.39.234"],timeout=5000)

class Logcollect :
    def __init__(self,plugins):
        print "++init++"
        
        self.__logidentify = LogIdentify()
        self.__plugins = plugins
    
    
    def collect(self,plugin,line,dst_ip):
        rules = plugin.get_plugin_rules()
        action = {}
        action["_id"] = str(uuid.uuid1())
        source_dict = {"message":line}
        for rule in rules:
            rule.feed(line)
            if rule.match():
                source_dict = rule.generate_event()
                source_dict["message"] = line
                source_dict["dst_ip"] = dst_ip
                break
                #print('Match rule: [%s] -> %s' % (rule.name, line))
        action["_source"] = source_dict   
        return action
     
        
    def collect_file(self,file,index_name,index_type,dst_ip):
        print file
        plugin = self.__logidentify.idendtify_logfile(self.__plugins, file)
        if plugin :
            print "collect---------"
            f = open(file,'rb') 
            actions = []
            i = 0
            for line in f:
                action_dict = self.collect(plugin, line,dst_ip)
                i += 1
                if action_dict: 
                    actions.append(action_dict)
                if (i == 10000):
                    bulk(client,actions,index=index_name,doc_type=index_type,chunk_size=2000)
                    i = 0
                    actions = []
                    print "success"
            print "success"
            bulk(client,actions,index=index_name,doc_type=index_type,chunk_size=2000)
            f.close() 
        
    
    
    
    def collect_dir(self,path,index_name,index_type,dst_ip):  
        for root ,dirs,files in os.walk(path):
            for file in files:
               if os.path.splitext(file)[1] == '.log' or os.path.splitext(file)[1] == '.txt':
                   self.collect_file(os.path.join(root,file),index_name,index_type,dst_ip)
            for dir in dirs:
                self.collect_dir(dir,index_name,index_type,dst_ip)