import cherrypy
import controllers.module as module

import splunk, splunk.search, splunk.util, splunk.entity
import json
from splunk.appserver.mrsparkle.lib import jsonresponse
import lib.util as util
import lib.i18n as i18n

import logging
logger = logging.getLogger('splunk.module.sitehopping')

import math
import cgi
import os
import re

def find_node_pos(container, name):
    for i in range(len(container)):
        if container[i]['name'] == name:
            return i
    return -1

class sitehopping(module.ModuleHandler):

    def generateResults(self, host_app, client_app, sid, count=1000, 
            offset=0, entity_name='results'):

        count = max(int(count), 0)
        offset = max(int(offset), 0)
        if not sid:
            raise Exception('hpviz-sitehopping.generateResults - sid not passed!')

        try:
            job = splunk.search.getJob(sid)
        except splunk.ResourceNotFound, e:
            logger.error('hpviz-sitehopping could not find job %s. Exception: %s' % (sid, e))
            return _('<p class="resultStatusMessage">Could not get search data.</p>')
        dataset = getattr(job, entity_name)[offset: offset+count]
        fieldNames = [x for x in getattr(job, entity_name).fieldOrder if (not x.startswith('_'))]
        events = []
        fields = ('To_Node', 'From_Node')
        for i, result in enumerate(dataset):
            event = {}
            for field in fieldNames:
                event[field] = str(result.get(field, None))
                if event[field] == 'None':
                    event.pop(field)
                events.append(event)
        nodes = []
        links = []
        """
        group 1: Landding Site
        group 2: Hopping Site
        group 3: malware
        """
        for row in events:
            if 'From_Node' in row.keys():
                l_pos = find_node_pos(nodes, row['From_Node'])
                if l_pos == -1:
                    l_node = {}
                    l_node['name'] = row['From_Node']
                    l_node['group'] = 1
                    l_node['size'] = 300
                    nodes.append(l_node)

                to_list = []
                for n in row['To_Node'].split(','):
                    if n != row['From_Node']:
                        to_list.append(n)
                    
                for n in to_list:
                    pos = find_node_pos(nodes, n)
                    if pos == -1:
                        h_node = {}
                        h_node['name'] = n
                        h_node['group'] = 2
                        h_node['size'] = 400
                    else:
                        nodes[pos]['group'] = 2
                        nodes[pos]['size'] = 300
                    link = {}
                    link['sourceName'] = row['From_Node']
                    link['targetName'] = n
                    links.append(link)
                    nodes.append(h_node)

        for n in nodes:
            if not re.search(r'[:/"]', n['name']):
                if re.search(r'[a-z0-9]{32}', n['name']):
                    n['group'] = 3
                    n['size'] = 400
        i = 0
        uni_id = {}
        ext_nodes = []
        for n in nodes:
            if n['name'] not in uni_id.keys():
                uni_id[n['name']] = i
                n['id'] = i
                i = i + 1
                ext_nodes.append(n)
        nodes = ext_nodes
        uni_links_name = []
        uni_links = []
        for l in links:
            uulink = str(l['sourceName']) + '_' + str(l['targetName'])
            if uulink not in uni_links_name:
                uni_links_name.append(uulink)
                l['source'] = uni_id[l['sourceName']]
                l['target'] = uni_id[l['targetName']]
                l.pop('sourceName')
                l.pop('targetName')
                uni_links.append(l)
        links = uni_links
 
        outputJSON = {}
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
