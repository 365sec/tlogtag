# -*- coding:utf-8 -*-

import re
import json
from syslog_log import *
import geoip2.database
import sys
default_encoding="utf-8"
if(default_encoding!=sys.getdefaultencoding()):
    reload(sys)
    sys.setdefaultencoding(default_encoding)
cn_list = ["局域网"]
cn_list = json.dumps(cn_list)
cn_list = json.loads(cn_list)

class RuleMatch(object):
    NEWLINE = '\\n'

    def __init__(self, name, rule, plugin):
      #  debug('Adding rule (%s)..' % name)
        self.rule = rule
        self.name = name
        self.plugin = plugin
        self.encode = plugin.get('config', 'encoding')
        self.lines = []
        self.n_matches = 0
        try:
            precheck = self.rule['precheck']
        except:
            precheck = ''

        regexp = self.rule['regexp']
        regex_flags = re.IGNORECASE | re.UNICODE
        for r in regexp.split(RuleMatch.NEWLINE):
            try:
                self.lines.append({'precheck': '',
                 'regexp': r,
                 'pattern': re.compile(r, regex_flags),
                 'result': None})
            except Exception as e:
                info('Error reading rule [%s]: %s' % (self.name, e))

        if len(self.lines) > 0:
            self.lines[0]['precheck'] = precheck
        self.nlines = regexp.count(RuleMatch.NEWLINE) + 1
        self.line_count = 1
        self.matched = False
        self.log = ''
        self.groups = {}
        self._replace_assessment = {}
        for key, value in self.rule.iteritems():
            if key != 'regexp':
                self._replace_assessment[key] = self.plugin.replace_value_assess(value)

        return

    def reset_rule(self):
        self.line_count = 1
        self.log = ''
        self.matched = False
        for line in self.lines:
            line['result'] = None

        return

    def feed(self, line):
        self.matched = False
        self.groups = {}
        line_index = self.line_count - 1
        if len(self.lines) > line_index:
            if line.find(self.lines[line_index]['precheck']) != -1:
                self.lines[line_index]['result'] = self.lines[line_index]['pattern'].search(line)
                if line_index == 0:
                    self.log = ''
                self.log += line.rstrip() + ' '
                if self.line_count == self.nlines:
                    if self.lines[line_index]['result'] is not None:
                        self.matched = True
                        self.line_count = 1
                    else:
                        self.log = ''
                        self.matched = False
                        self.line_count = 1
                elif self.lines[line_index]['result'] is not None:
                    self.line_count += 1
                else:
                    self.line_count = 1
        else:
            info('There was an error loading rule [%s]' % self.name)
        return

    def match(self):
        if self.matched:
            self.group()
            self.n_matches += 1
        return self.matched

    def group(self):
        self.groups = {}
        count = 1
        if self.matched:
            for line in self.lines:
                groups = line['result'].groups()
                for group in groups:
                    if group is None:
                        group = ''
                    value = ''
                    value = str(group.encode('utf-8'))
                    self.groups.update({str(count): value})
                    count += 1

                groups = line['result'].groupdict()
                for key, group in groups.iteritems():
                    if group is None:
                        group = ''
                    value = ''
                    value = str(group.encode('utf-8'))
                    self.groups.update({str(key): value})

        return

    def generate_event(self):
        try:
            event_type = self.rule['event_type']
        except KeyError:
            info('Event has no type, check plugin configuration!')
        source = {}
        for key, value in self.rule.iteritems():
            if key not in ('regexp', 'precheck'):
                source[key] = self.plugin.get_replace_value(value, self.groups, self._replace_assessment[key])
                ip_reg = re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',source[key])
                if ip_reg != None:
                    reader = geoip2.database.Reader('./././static/ip_info/GeoLite2-City.mmdb')
                    ip_reg1 = re.match('(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})',source[key])
                    if ip_reg1 != None:
                        key1 = key + "_address"
                        source[key1] = cn_list[0]
                    else:
                        try:
                            response = reader.city(source[key])
                            country = response.country.names['zh-CN']
                            province = response.subdivisions[0].names['zh-CN']
                            city = response.city.names['zh-CN']
                            context = country+" "+province+" "+city
                            key1 = key+"_address"
                            source[key1] = context
                        except:
                            pass
        return source
                
        
