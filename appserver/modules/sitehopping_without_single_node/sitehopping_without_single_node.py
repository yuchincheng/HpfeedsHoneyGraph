import cherrypy
import controllers.module as module

import splunk, splunk.search, splunk.util, splunk.entity
import json
from splunk.appserver.mrsparkle.lib import jsonresponse
import lib.util as util
import lib.i18n as i18n

import logging
logger = logging.getLogger('splunk.module.sitehopping_without_single_node')

import math
import cgi
import os
import re

def node_already_exists(container, c):
    for i in container:
        if i['name'] == str(c):
            return True
    return False


def id_of_node(container, c):
    for i in container:
        if i['name'] == c:
            return i['id']
    return False



class sitehopping_without_single_node(module.ModuleHandler):

    def generateResults(self, host_app, client_app, sid, count=1000, 
            offset=0, entity_name='results'):

        count = max(int(count), 0)
        offset = max(int(offset), 0)
        if not sid:
            raise Exception('hpviz-sitehopping_without_single_node.generateResults - sid not passed!')

        try:
            job = splunk.search.getJob(sid)
        except splunk.ResourceNotFound, e:
            logger.error('hpviz-sitehopping_without_single_node could not find job %s. Exception: %s' % (sid, e))
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
        lines = []
        for event in events:
            line = event['object2']
            lines.append(line)
        links = []
        i = 0
        nodes = []
        for l in lines:
            lsplit = l.split('-->')
            if lsplit[0] == '':
                continue
            link = {}
            if len(lsplit) == 2:
                if lsplit[0] == 'None':
                    continue
                    """
                    if not node_already_exists(nodes, lsplit[1]):
                        node = {}
                        node['name'] = lsplit[1]
                        node['groupName'] = 'Landding site'
                        node['group'] = 1
                        node['id'] = i
                        node['size'] = 300
                        i = i + 1
                        nodes.append(node)
                    """
                else:
                    if not node_already_exists(nodes, lsplit[0]):
                        node = {}
                        node['name'] = lsplit[0]
                        node['groupName'] = 'Landding site'
                        node['group'] = 1
                        node['id'] = i
                        node['size'] = 300
                        i = i + 1
                        nodes.append(node)
                    if not node_already_exists(nodes, lsplit[1]):
                        node = {}
                        node['name'] = lsplit[1]
                        node['groupName'] = 'Hopping site'
                        node['group'] = 2
                        node['id'] = i
                        node['size'] = 400
                        i = i + 1
                        nodes.append(node)
                    link['source'] = id_of_node(nodes, lsplit[0])
                    link['target'] = id_of_node(nodes, lsplit[1])
                    link['value'] = 1
                    links.append(link)
            elif len(lsplit) == 1:
                if not node_already_exists(nodes, lsplit[0]):
                    node = {}
                    node['name'] = lsplit[0]
                    node['groupName'] = 'Single link'
                    node['group'] = 3
                    node['id'] = i
                    node['size'] = 500
                    i = i + 1
                    nodes.append(node)
    
        for n in nodes:
            if not re.search(r'[:/"]', n['name']):
                if re.search(r'[a-z0-9]{32}', n['name']):
                    n['group'] = 4
                    n['groupName'] = 'Malware md5'
                    n['size'] = 500
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
