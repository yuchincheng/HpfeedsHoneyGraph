import cherrypy
import controllers.module as module

import splunk, splunk.search, splunk.util, splunk.entity
import json
from splunk.appserver.mrsparkle.lib import jsonresponse
import lib.util as util
import lib.i18n as i18n

import logging
logger = logging.getLogger('splunk.module.domainip')

import math
import cgi
import os

def search_in_list(container, field, value):
    for i in container:
        if i[field] == value:
            return True
    return False

def find_data(datas, field, value):
    pos = []
    for i in range(len(datas)):
        if datas[i][field] == value:
            pos.append(i)
    return pos

def get_sub_node_link(depth, name, datas, event_ip='', event_country=''):
    """
    depth = 1 :==> md5
        will not appear in this function.
    depth = 2 :==> hostname
        first enter depth
    depth = 3 :==> resolved ip
        if hostname of event do not exitst,
            this will be direct link to depth node
    depth = 4 :==> passive domain name
        second hostname enter
    depth = 5 :==> resolved ip
        final return point
    Each depth will return two list contain (nodes, links)
    """
    inner_nodes = []
    inner_links = []

    if depth == 5:
        return [], []
    if depth == 4:
        pos = find_data(datas, 'pff_domain', name)
        if len(pos) > 0:
            for n in pos:
                node = {}
                link = {}
                node['name'] = datas[n]['pff_ip']
                node['country'] = event_country
                if datas[n]['country_code'] != '':
                    node['country'] = datas[n]['country_code']
                node['group'] = 5
                tn, tl = get_sub_node_link(depth + 1, node['name'], datas)
                inner_nodes.extend(tn)
                inner_links.extend(tl)
                inner_nodes.append(node)
                link['sourceName'] = name
                link['targetName'] = node['name']
                inner_links.append(link)

    if depth == 3:
        pos = find_data(datas, 'pff_ip', name)
        if len(pos) > 0:
            for n in pos:
                node = {}
                link = {}
                node['name'] = datas[n]['pff_domain']
                pos2 = find_data(datas, 'pff_domain', node['name'])
                if len(pos2) > 0:
                    node['country'] = []
                    for i in pos2:
                        if datas[i]['country_code'] != '':
                            node['country'].append(datas[n]['country_code'])
                else:
                    node['country'] = event_country
                node['group'] = 4
                tn, tl = get_sub_node_link(depth + 1, node['name'], datas)
                inner_nodes.extend(tn)
                inner_links.extend(tl)
                inner_nodes.append(node)
                link['sourceName'] = name
                link['targetName'] = node['name']
                inner_links.append(link)

    if depth == 2:
        pos = find_data(datas, 'pff_domain', name)
        if len(pos) > 0:
            for n in pos:
                node = {}
                link = {}
                node['name'] = datas[n]['pff_ip']
		node['country'] = event_country
                if datas[n]['country_code'] != '':
                    node['country'] = datas[n]['country_code']
                node['group'] = 3
                tn, tl = get_sub_node_link(depth + 1, node['name'], datas, event_ip, event_country)
                inner_nodes.extend(tn)
                inner_links.extend(tl)
                inner_nodes.append(node)
                link['sourceName'] = name
                link['targetName'] = node['name']
                inner_links.append(link)
        else:
            node = {}
            link = {}
            node['name'] = event_ip
            node['country'] = event_country
            node['group'] = 3
            tn, tl = get_sub_node_link(depth + 1, node['name'], datas, event_ip, event_country)
            inner_links.extend(tl)
            inner_nodes.extend(tn)
            inner_nodes.append(node)
            link['sourceName'] = name
            link['targetName'] = node['name']
            inner_links.append(link)

    return inner_nodes, inner_links

class domainip(module.ModuleHandler):
    csv_path = 'dnsip.csv'
    seq = ('pff_ip', 'pff_domain', 'country_code', 'geo_lat', 'geo_long')

    def generateResults(self, host_app, client_app, sid, count=1000, 
            offset=0, entity_name='results'):

        count = max(int(count), 0)
        offset = max(int(offset), 0)
        if not sid:
            raise Exception('hpviz-domainip.generateResults - sid not passed!')

        try:
            job = splunk.search.getJob(sid)
        except splunk.ResourceNotFound, e:
            logger.error('hpviz-domainip could not find job %s. Exception: %s' % (sid, e))
            return _('<p class="resultStatusMessage">Could not get search data.</p>')
        
        dataset = getattr(job, entity_name)[offset: offset+count]
        fieldNames = [x for x in getattr(job, entity_name).fieldOrder if (not x.startswith('_'))]

        self.csv_path = os.path.join('/opt/splunk/etc/apps/HpfeedsHoneyGraph/lookups', self.csv_path)
        outputJSON = {}

        datas = []
        with open(self.csv_path, 'r') as fin:
            raw_in = fin.readlines()
        for row in raw_in[1:]:
            tmp = {}
            tl = row.split(',')
            for i in range(3):
                tmp[self.seq[i]] = tl[i].strip()
            datas.append(tmp)
        del raw_in
        events = []
        for i, result in enumerate(dataset):
            event = {}
            for field in fieldNames:
                event[field] = str(result.get(field, None))
            events.append(event)

        outputJSON['events'] = events
        nodes = []
        links = []
        node_root = {}
        node_root['name'] = 'Cuckoo'
        node_root['group'] = 0
        nodes.append(node_root)
        for event in events:
            node = {}
            node['name'] = event['md5']
            node['group'] = 1
            nodes.append(node)
            tl = {}
            tl['sourceName'] = 'Cuckoo'
            tl['targetName'] =  node['name']
            tl['value'] = 1
            links.append(tl)
            if event['hostname'] == 'None':
                if not search_in_list(nodes, 'name', event['dnsinfo'].split('@')[1]):
                    i_node = {}
                    i_node['name'] = event['dnsinfo'].split('@')[1]
                    if i_node['name'] == '':
                        continue
                    i_node['group'] = 3
                    i_node['country'] = event['dnsinfo'].split('@')[2]
                    nodes.append(i_node)
                link = {}
                link['sourceName'] = node['name']
                link['targetName'] = event['dnsinfo'].split('@')[1]
                link['value'] = 1
                links.append(link)
            else:
                hostname_list = event['hostname'].split(',')
                event_ip = event['dnsinfo'].split(',')
                event_hostname_ips = []
                for hn in hostname_list:
                    tmp = [hn, '', '']
                    for eip in event_ip:
                        if eip.split('@')[0] == hn:
                            tmp[1] = eip.split('@')[1]
                            tmp[2] = eip.split('@')[2]
                            break
                    event_hostname_ips.append(tmp)
                for hn, eip, ectry in event_hostname_ips:
                    if not search_in_list(nodes, 'name', hn):
                        h_node = {}
                        pos = find_data(datas, 'pff_domain', hn)
                        h_node['country'] = ectry
                        if len(pos) > 0:
                            h_node['country'] = []
                            for i in range(len(pos)):
                                if datas[pos[i]]['country_code'] != '':
                                    if not datas[pos[i]]['country_code'] in h_node['country']:
                                        h_node['country'].append(datas[pos[i]]['country_code'])
                        h_node['name'] = hn
                        h_node['group'] = 2
                        nodes.append(h_node)
                    link = {}
                    link['sourceName'] = node['name']
                    link['targetName'] = hn
                    link['value'] = 1
                    links.append(link)
                    tn, tl = get_sub_node_link(2, hn, datas, eip, ectry)
                    links.extend(tl)
                    nodes.extend(tn)

        exists_nodes = []
        exists_names = []
        for n in nodes:
            if n['name'] == "":
                continue
            if not n['name'] in exists_names:
                exists_names.append(n['name'])
                exists_nodes.append(n)

        nodes = exists_nodes
        name_id = {}
        i = 0
        for n in nodes:
            n['id'] = i
            name_id[n['name']] = n['id']
            i = i + 1
        nodes.sort(key=lambda x:x['id'])
        final_links = []
        for l in links:
            if l['targetName'] == '':
                continue
            l['source'] = name_id[l['sourceName']]
            l['target'] = name_id[l['targetName']]
            l.pop('targetName')
            l.pop('sourceName')
            final_links.append(l)

        links = final_links
        exists_pairs = []
        exists_links = []
        for l in links:
            l_p = str(l['source'])+'_'+str(l['target'])
            if not l_p in exists_pairs:
                exists_pairs.append(l_p)
                exists_links.append(l)
    
        links = exists_links

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
