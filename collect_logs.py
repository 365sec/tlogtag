# -*- coding:utf-8 -*-

import os
import json
from django.shortcuts import render,HttpResponse

def collect_logs(request):
    if request.method == "POST":
        index_name = request.POST["path"]
        index_type = request.POST["id"]
        fpath = request.POST["fpath"]
        f = open('././status/status','r')
        status_dict = json.loads(f.read())
        task_id = status_dict["task_id"]
        ft1 = open('././status/task_detail','r') #修改关联状态
        task_list1 = json.loads(ft1.read())
        for task in task_list1:
            if task["task_id"]==task_id:
                for asset_info in task["asset_info"]:
                    if asset_info["id"] == index_type:
                        asset_info["related_status"] = "2"
                        break
                break
#         workpath = os.getcwd()
#         print workpath
        path = fpath.replace('\\','/',20)
        ft = open('././status/task_detail','r') 
        task_list = json.loads(ft.read())
        for task in task_list:
            if task["task_id"]==task_id:
                for asset_info in task["asset_info"]:
                    if asset_info["id"] == index_type:
                        dest_ip = asset_info["ip"]
#         path1 = os.path.join(os.path.dirname(os.path.realpath(__file__)),"collect")
#         os.chdir(path1)
        cmd = "python ./log_analysis/collect_logs/collect/tlogtag.py "+path+" "+index_name+" "+index_type+" "+dest_ip
        os.system(cmd)  #采集日志到es
#         os.chdir(workpath)  #把工作目录改回原有
        f = open('././status/status','r')
        status_dict = json.loads(f.read())
        task_id = status_dict["task_id"]
        ft = open('././status/task_detail','r') #修改关联状态
        task_list = json.loads(ft.read())
        for task in task_list:
            if task["task_id"]==task_id:
                for asset_info in task["asset_info"]:
                    if asset_info["id"] == index_type:
                        asset_info["related_status"] = "1"
                        break
                break
        task_content = json.dumps(task_list)
        fw = open('././status/task_detail','w')
        fw.write(task_content)
        fw.close()
        content = {
                   "msg":"关联成功，已开始分析",
                   "success":True
                   }
        return HttpResponse(json.dumps(content))
    else:
        return HttpResponse("")
def get_index_name(request):
    if request.method == "POST":
        index_name = request.POST["path"]
        content = {
                   "dbName":index_name,
                   "success":True
                   }
        return HttpResponse(json.dumps(content))
    else:
        return HttpResponse("")
        
        
        
# path1 = os.path.join(os.path.dirname(os.path.realpath(__file__)),"collect")
# os.chdir(path1)
# path = "D:\logs"
# cmd = "python tlogtag.py "+path
# os.system(cmd)




