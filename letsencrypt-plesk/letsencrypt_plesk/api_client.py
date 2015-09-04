"""PleskApiClient"""

import os
import sys
import subprocess
import requests
import logging

from xml.dom.minidom import Document, parseString

logger = logging.getLogger(__name__)


class PleskApiClient(object):
    """Class performs API-RPC requests to Plesk"""

    CLI_PATH = "/usr/local/psa/bin/"
    BIN_PATH = "/usr/local/psa/admin/bin/"

    def __init__(self, host='127.0.0.1', port=8443, key=None):
        self.host = host
        self.port = port
        self.scheme = 'https' if port == 8443 else 'http'
        self.secret_key = key if key else self._get_secret_key()

    def request(self, request):
        if isinstance(request, dict):
            request = str(dict2xml(request))
        logger.debug("Plesk API-RPC request: %s", request)
        headers = {'Content-type': 'text/xml', 'HTTP_PRETTY_PRINT': 'TRUE', 'KEY': self.secret_key}
        response = requests.post(
            "{scheme}://{host}:{port}/enterprise/control/agent.php".format(
                scheme=self.scheme,
                host=self.host,
                port=self.port
            ),
            verify=False,
            headers=headers,
            data=request
        )
        logger.debug("Plesk API-RPC response: %s", response.text)
        return xml2dict(response.text)

    def _get_secret_key(self):
        self.secret_key_created = True
        return self.execute(self.CLI_PATH + "secret_key",
                            ["--create", "-ip-address", "127.0.0.1", "-description", __name__])

    def cleanup(self):
        """Remove secret key from Plesk"""
        if self.secret_key and self.secret_key_created:
            self.execute(self.CLI_PATH + "secret_key", ["--delete", "-key", self.secret_key])

    def execute(self, command, arguments=[], stdin=None, environment={}):
        for name, value in environment.items():
            os.environ[name] = value

        logger.debug("Plesk exec: %s", " ".join([command] + arguments))
        return subprocess.check_output([command] + arguments, stdin=stdin)

    def filemng(self, args):
        return self.execute(self.BIN_PATH + "filemng", args)

class dict2xml(object):

    def __init__(self, structure):
        self.doc = Document()

        rootName = str(structure.keys()[0])
        self.root = self.doc.createElement(rootName)

        self.doc.appendChild(self.root)
        self.build(self.root, structure[rootName])

    def build(self, father, structure):
        if isinstance(structure, dict):
            for k in structure:
                tag = self.doc.createElement(k)
                father.appendChild(tag)
                self.build(tag, structure[k])

        elif isinstance(structure, list):
            grandFather = father.parentNode
            tagName = father.tagName
            grandFather.removeChild(father)
            for l in structure:
                tag = self.doc.createElement(tagName)
                self.build(tag, l)
                grandFather.appendChild(tag)

        else:
            data = str(structure)
            tag = self.doc.createTextNode(data)
            father.appendChild(tag)

    def __str__(self):
        return self.doc.toprettyxml()


class xml2dict(dict):

    def __init__(self, data):
        dom = parseString(data)
        structure = {dom.documentElement.tagName: self._get_children(dom.documentElement)}
        super(xml2dict, self).__init__(structure)

    def _get_children(self, node):
        if node.nodeType == node.TEXT_NODE:
            return node.data

        children = {}
        for child in node.childNodes:
            if child.nodeType == child.TEXT_NODE:
                if 0 == len(child.data.strip()):
                    continue
                elif isinstance(children, list):
                    children = children + [child.data]
                elif isinstance(children, dict):
                    children = child.data
                else:
                    children = [children, child.data]
            elif child.tagName in children:
                if isinstance(children[child.tagName], list):
                    children[child.tagName] = children[child.tagName] + [self._get_children(child)]
                else:
                    children[child.tagName] = [children[child.tagName], self._get_children(child)]
            else:
                children[child.tagName] = self._get_children(child)
        return children
