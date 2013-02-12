import cherrypy
import controllers.module as module

import splunk, splunk.search, splunk.util, splunk.entity
import json
from splunk.appserver.mrsparkle.lib import jsonresponse
import lib.util as util
import lib.i18n as i18n

import logging
logger = logging.getLogger('splunk.module.treecountry')

import math
import cgi
import os

def find_name_in_container(container, name, field):
    for i in range(len(container)):
        if container[i][field] == name:
            return True, i
    return False, -1

class treecountry(module.ModuleHandler):

    def generateResults(self, host_app, client_app, sid, count=1000, 
            offset=0, entity_name='results'):

        count = max(int(count), 0)
        offset = max(int(offset), 0)
        if not sid:
            raise Exception('hpviz-treecountry.generateResults - sid not passed!')

        try:
            job = splunk.search.getJob(sid)
        except splunk.ResourceNotFound, e:
            logger.error('hpviz-treecountry could not find job %s. Exception: %s' % (sid, e))
            return _('<p class="resultStatusMessage">Could not get search data.</p>')
        
        dataset = getattr(job, entity_name)[offset: offset+count]
        fieldNames = [x for x in getattr(job, entity_name).fieldOrder if (not x.startswith('_'))]
        events = []
        for i, result in enumerate(dataset):
            event = {}
            for field in fieldNames:
                event[field] = str(result.get(field, None))
                if event[field] == 'None':
                    event.pop(field)
                events.append(event)

        full_keys = ('objects', 'values(H1)', 'values(H2)')
        
        root = {}
        root['name'] = 'By Country'
        root['children'] = []
        root['group'] = 0
        for l in events:
            if not full_keys[1] in l.keys() and not full_keys[2] in l.keys():
                """ Events not found : Ignore this situation"""
                continue
        
            if full_keys[1] in l.keys() and full_keys[2] in l.keys():
                """ Group 3 Operation : ip_object ==> URL ==> md5 ==> hostname ==> hostIP"""
                continue
        
            if full_keys[1] in l.keys():
                """ Group 1 Operation : ip_object ==> URL ==> md5"""
                g1_str = l[full_keys[1]].replace(',', ' ')
                g1_list = g1_str.split()
                t_list = []
                for col in g1_list:
                    t_list.append([x for x in col.split('@@@')[1:]])
                judge, pos = find_name_in_container(root['children'], l[full_keys[0]], 'name')
                if judge:
                    croot = root['children'][pos]
                else:
                    croot = {}
                    croot['name'] = l[full_keys[0]]
                    croot['group'] = 1
                if 'children' not in croot.keys():
                    croot['children'] = []
                for g1 in t_list:
                    i_judge, i_pos = find_name_in_container(croot['children'], g1[0], 'name')
                    if not i_judge:
                        parent = {}
                        parent['group'] = 1
                        parent['name'] = g1[0]
                    else:
                        parent = croot['children'][i_pos]
                    if 'children' not in parent.keys():
                        parent['children'] = []
                    c_judge, _ = find_name_in_container(parent['children'], g1[1], 'name')
                    if not c_judge:
                        child = {}
                        child['name'] = g1[1]
                        child['group'] = 1
                        parent['children'].append(child)
                    if not i_judge:
                        croot['children'].append(parent)
                if not judge:
                    root['children'].append(croot)
                continue
        
            if full_keys[2] in l.keys():
                """ Group 2 Operation : ip_object ==> md5 ==> hostname ==> hostIP"""
                g2_str = l[full_keys[2]].replace(',', ' ')
                g2_list = g2_str.split()
                t_list = []
                for col in g2_list:
                    t_list.append([x for x in col.split('@@@')])
                judge, pos = find_name_in_container(root['children'], l[full_keys[0]], 'name')
                if judge:
                    croot = root['children'][pos]
                else:
                    croot = {}
                    croot['name'] = l[full_keys[0]]
                    croot['group'] = 2
                if 'children' not in croot.keys():
                    croot['children'] = []
                for g2 in t_list:
                    g_judge, g_pos = find_name_in_container(croot['children'], g2[0], 'name')
                    if not g_judge:
                        grand = {}
                        grand['group'] = 2
                        grand['name'] = g2[0]
                    else:
                        grand = croot['children'][g_pos]
                    if 'children' not in grand.keys():
                        grand['children'] = []
                    p_judge, p_pos = find_name_in_container(grand['children'], g2[1], 'name')
                    if not p_judge:
                        parent = {}
                        parent['name'] = g2[1]
                        parent['group'] = 2
                    else:
                        parent = grand['children'][p_pos]
                    if 'children' not in parent.keys():
                        parent['children'] = []
                    c_judge, _ = find_name_in_container(parent['children'], g2[2], 'name')
                    if not c_judge:
                        child = {}
                        child['name'] =g2[2]
                        child['group'] = 2
                        parent['children'].append(child)
                    if not p_judge:
                        grand['children'].append(parent)
                    if not g_judge:
                        croot['children'].append(grand)
        
                if not judge:
                    root['children'].append(croot)
        
                continue

        outputJSON = root
        cherrypy.response.headers['Content-Type'] = 'text/json'
        return json.dumps(outputJSON, sort_keys=True)
        #return self.render_json(outputJSON)
        
    def render_json(self, response_data, set_mime='text/json'):
        cherrypy.response.headers['Content-Type'] = set_mime

        if isinstance(response_data, jsonresponse.JsonResponse):
            response = response_data.toJson().replace("</", "<\\/")
        else:
            response = json.dumps(response_data).replace("</", "<\\/")

        # Pad with 256 bytes of whitespace for IE security issue. See SPL-34355
        return ' ' * 256  + '\n' + response
