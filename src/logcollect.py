# -*- coding:utf-8 -*-

import pymongo
from pymongo import MongoClient
from  identify  import LogIdentify
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import uuid
import ConfigParser
import os
import json

conf = ConfigParser.ConfigParser()
conf.read(os.path.join(os.path.dirname(__file__),"../../","log_analysis.cfg"))
# print conf.sections()
str_es_hosts = conf.get("elasticsearch", "hosts")
es_hosts = json.loads(str_es_hosts)
es_timeout = int(conf.get("elasticsearch", "timeout"))
client = Elasticsearch(hosts=es_hosts,timeout=es_timeout)

mongo_host = conf.get("mongodb", "host")
mongo_port = int(conf.get("mongodb", "port"))
mongo_client = MongoClient(mongo_host,mongo_port)


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
            mongo_actions = []
            i = 0
            mongo_db = mongo_client[index_name]
            collections = mongo_db[index_type]
            for line in f:
                action_dict = self.collect(plugin, line,dst_ip)
                mongo_dict = {}
                mongo_dict["original_text"] = (action_dict.get("_source",{})).get("message","")
                mongo_dict["checked"] = (action_dict.get("_source",{})).get("checked","0")
                mongo_dict["color"] = (action_dict.get("_source",{})).get("color","")
                mongo_dict["method"] = (action_dict.get("_source",{})).get("request_method","")
                mongo_actions.append(mongo_dict)
                i += 1
                if action_dict: 
                    actions.append(action_dict)
                if (i == 10000):
                    bulk(client,actions,index=index_name,doc_type=index_type,chunk_size=2000)
                    collections.insert_many(mongo_actions)
                    i = 0
                    mongo_actions = []
                    actions = []
                    print "success"
            print "success"
            bulk(client,actions,index=index_name,doc_type=index_type,chunk_size=2000)
            collections.insert_many(mongo_actions)
            f.close() 
        
    
    
    
    def collect_dir(self,path,index_name,index_type,dst_ip):  
        for root ,dirs,files in os.walk(path):
            for file in files:
               if os.path.splitext(file)[1] == '.log' or os.path.splitext(file)[1] == '.txt':
                   self.collect_file(os.path.join(root,file),index_name,index_type,dst_ip)
            for dir in dirs:
                self.collect_dir(dir,index_name,index_type,dst_ip)