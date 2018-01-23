import re
from plugin import Plugin
import os
from ConfigParser import Error as BaseConfigError
from Config import Conf
from logcollect import  Logcollect
import sys

DEFAULT_ENCODING = 'latin1'
DEFAULT_SECTION = 'DEFAULT'
CONFIG_SECTION = 'config'
PLUGIN_ID = 'plugin_id'


class WrongPluginError(BaseConfigError):
    pass

class Tlogtag:
    
    def __init__(self):
        print "__init__"
        self.__plugins_dir = os.path.join(os.path.dirname(__file__), 'plugins')
        self.__aliases = Conf()
        self.__configuration = Conf()
        self.__plugins =[]
        self.__configuration.read([os.path.join(os.path.dirname(__file__), 'config.cfg')], 'latin1')
        self.__aliases.read([os.path.join(os.path.dirname(__file__), 'aliases.cfg')], 'latin1')
        
    def __update_plugin_and_add_to_list(self, plugin):
        plugin.replace_aliases(self.__aliases)
        plugin.replace_config(self.__configuration)
        self.__plugins.append(plugin)
 
 
    def __create_plugin_from_path(self,conf_path, encoding = DEFAULT_ENCODING):
        if not os.path.exists(conf_path):
            raise WrongPluginError('Unable to read plugin configuration at (%s)' % conf_path)
        plugin = Plugin()
        plugin.read([conf_path], encoding)
        
        if plugin.has_option(CONFIG_SECTION, 'custom_functions_file'):
                self.__load_plugin_custom_functions(plugin.get(DEFAULT_SECTION, PLUGIN_ID), plugin.get(CONFIG_SECTION, 'custom_functions_file'))

        return plugin
    
    def __load_plugin_custom_functions(self, plugin_id, custom_plugin_functions_file):
        print('Loading custom plugin functions for pid: %s' % plugin_id)
        if os.path.isfile(custom_plugin_functions_file):
            f = open(custom_plugin_functions_file, 'rb')
            lines = f.read()
            result = re.findall('Start Function\\s+(\\w+)\n(.*?)End Function', lines, re.M | re.S)
            function_list = {}
            for name, function in result:
                print('Loading function: %s' % name)
                try:
                    exec function.strip() in function_list
                    function_name = '%s_%s' % (name, plugin_id)
                    print('Adding function :%s' % function_name)
                    setattr(Plugin, function_name, function_list[name])
                except Exception as e:
                    print('Custom function error: %s' % str(e))

        else:
            print('Custom plugin functions file does not exist!')
    
     
    def load_plugins(self):
        f_list = os.listdir(self.__plugins_dir)
        for i in f_list:
           if os.path.splitext(i)[1] == '.cfg':
              plugin = self.__create_plugin_from_path(os.path.join(self.__plugins_dir,i))
              self.__update_plugin_and_add_to_list(plugin)
              
              print i
    
     
    def collect_log(self,path):
        print path 
        lc = Logcollect(self.__plugins)
        lc.collect_dir(path)
        
        
    
        
if __name__ == "__main__":        
    dir = "/"
    print sys.argv
    if len(sys.argv) > 1:
        dir = sys.argv[1]
    t = Tlogtag()
    t.load_plugins()
    t.collect_log(dir)
  