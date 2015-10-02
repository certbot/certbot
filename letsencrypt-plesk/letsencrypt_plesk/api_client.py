"""PleskApiClient"""

import os
import subprocess
import requests
import logging

from letsencrypt import errors
from xml.dom.minidom import Document, parseString

logger = logging.getLogger(__name__)


class PleskApiClient(object):
    """Class performs API-RPC requests to Plesk"""

    CLI_PATH = "/usr/local/psa/bin/"
    BIN_PATH = "/usr/local/psa/admin/bin/"

    def __init__(self, host='127.0.0.1', port=8443, secret_key=None):
        self.host = host
        self.port = port
        self.scheme = 'https' if port == 8443 else 'http'
        self.secret_key_created = False
        self.secret_key = secret_key

    def request(self, request):
        """Perform API-RPC request to Plesk"""
        if isinstance(request, dict):
            request = str(DictToXml(request))
        logger.debug("Plesk API-RPC request: %s", request)
        headers = {
            'Content-type': 'text/xml',
            'HTTP_PRETTY_PRINT': 'TRUE',
            'KEY': self.get_secret_key(),
        }
        response = requests.post(
            "{scheme}://{host}:{port}/enterprise/control/agent.php".format(
                scheme=self.scheme,
                host=self.host,
                port=self.port),
            verify=False,
            headers=headers,
            data=request)
        logger.debug("Plesk API-RPC response: %s", response.text)
        return XmlToDict(response.text)

    def get_secret_key(self):
        """Retrieve secret key for Plesk API or creates a new one"""
        if self.secret_key:
            return self.secret_key
        self.secret_key = self.execute(self.CLI_PATH + "secret_key", [
            "--create", "-ip-address", "127.0.0.1", "-description", __name__,
        ])
        self.secret_key_created = True
        return self.secret_key

    def cleanup(self):
        """Remove secret key from Plesk if it was created"""
        if self.secret_key and self.secret_key_created:
            try:
                self.execute(self.CLI_PATH + "secret_key", [
                    "--delete", "-key", self.secret_key,
                ])
            except PleskApiException as e:
                logger.debug(str(e))

    def execute(self, command, arguments=None, stdin=None, environment=None):
        """Execute CLI utility"""
        for name, value in (environment or {}).items():
            os.environ[name] = value

        process_args = [command] + (arguments or [])
        logger.debug("Plesk exec: %s", " ".join(process_args))
        try:
            return subprocess.check_output(process_args, stdin=stdin)
        except subprocess.CalledProcessError as e:
            raise PleskApiException(e)

    def filemng(self, args):
        """File operations in Plesk are implemented in filemng util"""
        # TODO replace with ftp client
        return self.execute(self.BIN_PATH + "filemng", args)


class PleskApiException(errors.PluginError):
    """Plesk API execution error"""


class DictToXml(object):  # pylint: disable=too-few-public-methods
    """Map dictionary into XML"""

    def __init__(self, structure):
        self.doc = Document()

        root_name = str(structure.keys()[0])
        self.root = self.doc.createElement(root_name)

        self.doc.appendChild(self.root)
        self._build(self.root, structure[root_name])

    def _build(self, father, structure):
        if isinstance(structure, dict):
            for k in structure:
                tag = self.doc.createElement(k)
                father.appendChild(tag)
                self._build(tag, structure[k])

        elif isinstance(structure, list):
            grand_father = father.parentNode
            tag_name = father.tagName
            grand_father.removeChild(father)
            for l in structure:
                tag = self.doc.createElement(tag_name)
                self._build(tag, l)
                grand_father.appendChild(tag)

        else:
            data = str(structure)
            tag = self.doc.createTextNode(data)
            father.appendChild(tag)

    def __str__(self):
        return self.doc.toprettyxml()


class XmlToDict(dict):  # pylint: disable=too-few-public-methods
    """Map XML into dictionary"""

    def __init__(self, data):
        dom = parseString(data)
        root = dom.documentElement
        structure = {
            root.tagName: self._get_children(root)
        }
        super(XmlToDict, self).__init__(structure)

    def _get_children(self, node):
        if node.nodeType == node.TEXT_NODE:
            return node.data

        children = {}
        for child in node.childNodes:
            if child.nodeType == child.TEXT_NODE:
                data = child.data
                if 0 == len(data.strip()):
                    continue
                elif isinstance(children, list):
                    children = children + [data]
                elif isinstance(children, dict):
                    children = data
                else:
                    children = [children, data]

            elif child.tagName in children:
                if not isinstance(children[child.tagName], list):
                    children[child.tagName] = [children[child.tagName]]
                children[child.tagName].append(self._get_children(child))

            else:
                children[child.tagName] = self._get_children(child)
        return children

    def native(self):
        """Encode all utf8 strings."""
        # TODO encode utf8 by default and drop this method
        return {x.encode('utf8'):
                self._native_children(self[x]) for x in self}

    def _native_children(self, node):
        if isinstance(node, str):
            return node.encode('utf8')
        elif isinstance(node, list):
            return [self._native_children(x) for x in node]
        elif isinstance(node, dict):
            return {x.encode('utf8'):
                    self._native_children(node[x]) for x in node}
