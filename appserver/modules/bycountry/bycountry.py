import cherrypy
import controllers.module as module

import splunk, splunk.search, splunk.util, splunk.entity
import json
from splunk.appserver.mrsparkle.lib import jsonresponse
import lib.util as util
import lib.i18n as i18n

import logging
logger = logging.getLogger('splunk.module.bycountry')

import math
import cgi
import os

def already_exist_in_nodes(nodes, name):
    for i in range(len(nodes)):
        if nodes[i]['name'] == name:
            return True, i
    return False, -1


class bycountry(module.ModuleHandler):

    def generateResults(self, host_app, client_app, sid, count=1000, 
            offset=0, entity_name='results'):

        count = max(int(count), 0)
        offset = max(int(offset), 0)
        if not sid:
            raise Exception('hpviz-bycountry.generateResults - sid not passed!')

        try:
            job = splunk.search.getJob(sid)
        except splunk.ResourceNotFound, e:
            logger.error('hpviz-bycountry could not find job %s. Exception: %s' % (sid, e))
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
        outputJSON = {}
        nodes = []
        links = []
        for event in events:
            try:
                if event['values(H1)']:
                    h1_list = event['values(H1)'].split()
                    for h1 in h1_list:
                        result = h1.split('@@@')
                        link = {};
                        exist, pos = already_exist_in_nodes(nodes, event['objects'])
                        if not exist:
                            f_node = {}
                            f_node['name'] = event['objects']
                            f_node['info_lable'] = []
                            f_node['info_lable'].append(result[0])
                            f_node['group'] = 1
                            f_node['size'] = 400
                            nodes.append(f_node)
                        else:
                            nodes[pos]['info_lable'].append(result[0])
                        exist, _ = already_exist_in_nodes(nodes, result[1])
                        if not exist:
                            t_node = {}
                            t_node['name'] = result[1]
                            t_node['group'] = 2
                            t_node['size'] = 500
                            nodes.append(t_node)
                        link['sourceUni'] = event['objects']
                        link['targetUni'] = result[1]
                        link['value'] = 1
                        links.append(link)
            except KeyError:
                pass
        
            try:
                if event['values(H2)']:
                    h2_list = event['values(H2)'].split()
                    for h2 in h2_list:
                        link = {};
                        exist, _ = already_exist_in_nodes(nodes, h2.split('@@@')[0])
                        if not exist:
                            f_node = {}
                            f_node['name'] = h2.split('@@@')[0]
                            f_node['group'] = 2
                            f_node['size'] = 500
                            nodes.append(f_node)
                        exist, _ = already_exist_in_nodes(nodes, h2.split('@@@')[1])
                        if not exist:
                            t_node = {}
                            t_node['name'] = h2.split('@@@')[1]
                            t_node['group'] = 3
                            t_node['size'] = 600
                            nodes.append(t_node)
                        link['sourceUni'] = h2.split('@@@')[0]
                        link['targetUni'] = h2.split('@@@')[1]
                        link['value'] = 1
                        links.append(link)
            except KeyError:
                pass
        
            try:
                if event['values(H3)']:
                    h3_list = event['values(H3)'].split()
                    for h3 in h3_list:
                        link = {};
                        exist, _ = already_exist_in_nodes(nodes, h3.split('@@@')[0])
                        if not exist:
                            f_node = {}
                            f_node['name'] = h3.split('@@@')[0]
                            f_node['group'] = 3
                            f_node['size'] = 600
                            nodes.append(f_node)
                        exist, _ = already_exist_in_nodes(nodes, h3.split('@@@')[1])
                        if not exist:
                            t_node = {}
                            t_node['name'] = h3.split('@@@')[1]
                            t_node['group'] = 4
                            t_node['size'] = 700
                            nodes.append(t_node)
                        link['sourceUni'] = h3.split('@@@')[0]
                        link['targetUni'] = h3.split('@@@')[1]
                        link['value'] = 1
                        links.append(link)
            except KeyError:
                pass
        i = 0
        uni_id = {}
        for n in nodes:
            uni_id[n['name']] = i
            n['id'] = i
            i = i + 1
        
        for l in links:
            l['source'] = uni_id[l['sourceUni']]
            l['target'] = uni_id[l['targetUni']]
            l.pop('sourceUni')
            l.pop('targetUni')
        
        nodes.sort(key=lambda x:x['id'])
        outputJSON['nodes'] = nodes
        outputJSON['links'] = links



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
