#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import os.path
import logging

from enum import Enum

commentRegex = '#.*'
directiveRegex = '([^\s]+)\s*(.+)'
sectionOpenRegex = '<([^/\s>]+)\s*([^>]+)?>'
sectionCloseRegex = '</([^\s>]+)\s*>'
driveLetterBeginsRegex = '^[a-zA-Z]:\\)*'
logger = logging.getLogger(__name__)

class Type(Enum):

	NONE = 1
	COMMENT = 2
	DIRECTIVE = 3
	TAG = 4


class ConfigNode:

	def __init__(
		self,
		name,
		content,
		parent,
		):

		self.name = name
		self.content = content
		self.children = list()
		self.parent = parent
		self.nodeType = Type.NONE
		self.startLine = None
		self.endLine = None
		self.filePath = None

	def createRootNode():
		return ConfigNode(None, None, None)

	def createChildNode(
		name,
		content,
		parent,
		nodeType,
		startLine,
		endLine,
		filePath
		):

		child = ConfigNode(name, content, parent)
		child.nodeType = nodeType
		child.startLine = startLine
		child.endLine = endLine
		child.filePath = filePath
		parent.children.append(child)
		return child


class WinApacheParser(object):

	def __init__(
		self,
		basepath,
		):

		self.basepath = basepath
	
	
	def getNodesOfType(self,nodeType,currentNode):
		matchingNodes = list()
		for node in currentNode.children:
			if(node.nodeType == nodeType):
				matchingNodes.append(node)
				
		return matchingNodes
	
	def getNodesOfName(self,name,currentNode):
		matchingNodes = list()
		for node in currentNode.children:
			if(node.name == name):
				matchingNodes.append(node)
				
		return matchingNodes
	
	def unsaved_files(self):
		return []
	
	def save(self,save_files):
		return []

	def parse(self,filePath):
		if not os.path.exists(filePath):
			return None
		with open(filePath) as fp:
			currentNode = ConfigNode.createRootNode()
			currentNode.filePath = filePath
			for (cnt, line) in enumerate(fp):
				cnt=cnt+1
				if re.match(commentRegex, line.strip()):
					continue
				elif re.match(sectionOpenRegex, line.strip()):
					name = re.match(sectionOpenRegex, line.strip()).group(1)
					content = re.match(sectionOpenRegex, line.strip()).group(2)
					sectionNode = ConfigNode.createChildNode(
						name,
						content,
						currentNode,
						Type.TAG,
						cnt,
						cnt,
						filePath
						)
					currentNode = sectionNode
				elif re.match(sectionCloseRegex, line.strip()):
					currentNode.endLine = cnt
					currentNode = currentNode.parent
				elif re.match(directiveRegex, line.strip()):
					name = re.match(directiveRegex, line.strip()).group(1)
					content = re.match(directiveRegex, line.strip()).group(2)
					ConfigNode.createChildNode(
						name,
						content,
						currentNode,
						Type.DIRECTIVE,
						cnt,
						cnt,
						filePath
						)

				#print(line)

			return currentNode
	
	def findNestedNodes(self,nodeList,filepath):
		node = self.parse(filepath)
		if node is None:
			return
		
		nodeList.add(node)
		for directiveNode in self.getNodesOfName("Include",node):
			filePath = self.sanitizePath(directiveNode.content)
			self.findNestedNodes(nodeList,filePath)
		for tagNode in self.getNodesOfType(Type.TAG,node):
			if len(tagNode.children)>0:
				for directiveNode in self.getNodesOfName("Include",tagNode):
					filePath = self.sanitizePath(directiveNode.content)
					self.findNestedNodes(nodeList,filePath)

	def findVirtualHosts(self,virtualHosts,currentNode):
		for node in currentNode.children:
				if(node.nodeType == Type.TAG and node.name.casefold() == "virtualhost".casefold()):
					virtualHosts.add(node)
	
	def findIncludeDirectives(self,includeList,currentNode):
		for node in currentNode.children:
			if(node.nodeType == Type.DIRECTIVE and node.name.casefold() == "include".casefold()):
				includeList.add(node)
	
	def findListenDirectives(self,listenList,currentNode):
		for node in currentNode.children:
				if(node.nodeType == Type.DIRECTIVE and node.name.casefold() == "listen".casefold()):
					listenList.add(node)

	def add_dir_beginning(self,vhost,typeToAdd,data):
		print("Opening file:{0} atvhost:{1}".format(vhost.node.filePath,vhost.node.content))
		contents = []
		with open(vhost.node.filePath,'r') as fp:
			contents = fp.readlines()
		if len(contents)>0:
			startline = [i for i, s in enumerate(contents) if s.find(vhost.node.content.strip())>-1 and s.casefold().find("<virtualhost")>-1]
			print("Inserting at line:{0}".format(startline[0]))
			with open(vhost.node.filePath,'w') as fp:
				if " " in data:
					contents.insert(vhost.node.startLine,"{0} \"{1}\"\n".format(typeToAdd,data.replace("\\","/")))
				else:
					contents.insert(vhost.node.startLine,"{0} {1}\n".format(typeToAdd,data.replace("\\","/")))
				fp.write( "".join(contents));
	
	def add_dir(self,vhost,typeToAdd,data):
		#print("add_dir Opening file:{0} vhost:{1}".format(vhost.node.filePath,vhost.node.content))
		logger.info("add_dir Opening file %s to update vhost :%s with startLine-%s and endLine-%s with typeToAdd-%s of data-%s",
			  vhost.node.filePath,vhost.node.content,vhost.node.startLine,vhost.node.endLine,typeToAdd,data )

		
		contents = []
		with open(vhost.node.filePath,'r') as fp:
			contents = fp.readlines()
			startline = [i for i, s in enumerate(contents) if s.find(vhost.node.content.strip())>-1 and s.casefold().find("virtualhost")>-1 and i >= (vhost.node.startLine-1)]
			logger.info("startline-%s",startline[0])
			#print("Start line:{0}".format(startline[0]))
			endLine = [i for i, s in enumerate(contents) if s.casefold().find("/virtualhost")>-1 and i > startline[0] and i <= vhost.node.endLine]
			logger.info("endLine-%s", endLine)
			#print("end line:{0}".format(endLine[0]))
		if len(contents)>0:
			with open(vhost.node.filePath,'w') as fp:
				if " " in data:
					contents.insert(endLine[0]-1,"{0} \"{1}\"\n".format(typeToAdd,data.replace("\\","/")))
				else:
					contents.insert(endLine[0]-1,"{0} {1}\n".format(typeToAdd,data.replace("\\","/")))
				fp.write( "".join(contents))
	
	def add_dir_raw(self,vhost,typeToAdd,data):
		print("Opening file:{0} atline:{1}".format(vhost.node.filePath,vhost.node.endLine-1))
		contents = []
		with open(vhost.node.filePath,'r') as fp:
			contents = fp.readlines()
		if len(contents)>0:
			with open(vhost.node.filePath,'w') as fp:
				contents.insert(vhost.node.endLine-1,"{0} {1}\n".format(typeToAdd,data.replace("\\","/")))
				fp.write( "".join(contents))
	
	def revert_challenge(self,filePath):
		virtualHosts = set()
		nestedNodes = set()
		print("Reverting challenges")
		self.findNestedNodes(nestedNodes,filePath)
		for node in nestedNodes:
			self.findVirtualHosts(virtualHosts,node)
		
		includeList = set()
		for vhost in virtualHosts:
			self.findIncludeDirectives(includeList,vhost)
		
		for includes in includeList:
			content=[]
			print("Checking files to remove in :{0} with content:{1}".format(includes.filePath,includes.content))
			with open(includes.filePath,'r') as fp:
				content = fp.readlines()
			removeLine = False
			filePathToDelete = self.sanitizePath(includes.content)
			print("deleting occurence of file:{0} at line:{1}".format(filePathToDelete,includes.startLine))
			if not os.path.isfile(filePathToDelete):
				removeLine = True
			if removeLine:
				indices = [i for i, s in enumerate(content) if includes.content in s]
				print("Removing:{0}".format(content.pop(indices[0])))
				
			with open(includes.filePath,'w') as fp:
				fp.write("".join(content))

	def sanitizePath(self,pathToSanitize):
		sanitizedPath = pathToSanitize.strip().replace("\\\\","/").replace("\"","")
		if re.match(driveLetterBeginsRegex,sanitizedPath) is None:
				sanitizedPath = "{0}/{1}".format(self.basepath,sanitizedPath)
		return sanitizedPath
	
	def update_directive(self,vhost,directive,data):
		#print("Opening file:{0} updating vhost at line:{1}".format(vhost.node.filePath,vhost.node.startLine))
		logger.info("Opening file:%s updating vhost at line:%s updating directive- %s with data- %s", 
			  vhost.node.filePath,vhost.node.startLine, directive, data)
		contents = []
		with open(vhost.node.filePath,'r') as fp:
			contents = fp.readlines()
		if len(contents)>0:
			with open(vhost.node.filePath,'w') as fp:
				startline= []
				endLine= []
				#print("replacing cert and key for vhost {0}-{1}".format(vhost.node.startLine,vhost.node.endLine))
				logger.info("replacing cert and key for vhost %s - %s", vhost.node.startLine,vhost.node.endLine)
				startline = [i for i, s in enumerate(contents) if s.find(vhost.node.content.strip())>-1 and s.casefold().find("virtualhost")>-1 and i >= (vhost.node.startLine-1)]
				logger.info("startline-%s",startline)
				for i, linedata in enumerate(contents):
					if linedata.casefold().find("/virtualhost")>-1 and i >= vhost.node.startLine and 1 <= vhost.node.endLine :
						logger.info("EndlineNo-%s, lineData: %s",i, linedata)
						endLine.append(i)
				logger.info("endLine-%s", endLine)

				startline=startline[0]
				endLine=endLine[0]
				indices = [i for i, s in enumerate(contents) if i>=startline and i<=endLine and directive in s]				
				logger.info("indices- %s,startline- %s,endLine- %s, directive- %s, data- %s",  indices,startline,endLine,directive, data)
				if len(indices)>0:
					#print("Popping line:{0}".format(indices[0]))
					logger.info("Popping line: %s", indices[0])
					contents.pop(indices[0])
					contents.insert(indices[0],"{0} \"{1}\"\n".format(directive,data.replace("\\","/")))
				else:
					logger.info("Adding cert derictive based on vhost endline")
					contents.insert(endLine-1,"{0} \"{1}\"\n".format(directive,data.replace("\\","/")))
				
				fp.write( "".join(contents))
	
	def update_virtualhost_address(self,vhost,port,isAddListen,isAddDummyVhost=False):
		print("updating virtualhost address Opening file:{0} updating vhost at line:{1}".format(vhost.node.filePath,vhost.node.startLine))
		contents = []
		with open(vhost.node.filePath,'r') as fp:
			contents = fp.readlines()
		if len(contents)>0:
			with open(vhost.node.filePath,'w') as fp:
				print("replacing virtual host {0}-{1}".format(vhost.node.startLine,vhost.node.endLine))
				print("Data:{0}".format(vhost.node.content.strip().casefold()))
				indices = [i for i, s in enumerate(contents) if s.casefold().find("virtualhost")>-1 and s.strip().casefold().find(vhost.node.content.strip().casefold())>-1]
				print(indices)
				if len(indices)>0:
					Variable=contents[indices[0]]
					print(Variable)
					print("Popping line:{0}".format(indices[0]))
					contents.pop(indices[0])
					dummyVhost=""
					if(isAddDummyVhost):
						dummyVhost="<VirtualHost *:80>\nDocumentRoot \"${SRVROOT}/htdocs\"\n</VirtualHost>\n"
									
					if isAddListen:
						if Variable.find("*")>-1 or Variable.find("_default_")>-1:
							contents.insert(indices[0],"{3}Listen {1}\r\n{0}{1}{2}".format(Variable[:Variable.index(":")+1],port,Variable[Variable.index(">"):],dummyVhost))
						else:
							m = re.search(r' .*\>', Variable)
							contents.insert(indices[0],"{4}Listen {3}:{1}\n{0}{1}{2}".format(Variable[:Variable.index(":")+1],port,Variable[Variable.index(">"):],m.group(0)[:-4],dummyVhost))

					else:
						contents.insert(indices[0],"{3}{0}{1}{2}".format(Variable[:Variable.index(":")+1],port,Variable[Variable.index(">"):],dummyVhost))
								
				fp.write( "".join(contents))


if __name__ == '__main__':
	nodeList = set()
	virtualHosts = set()
	basepath='C:/Apache24/'
	filepath = basepath+'/conf/httpd.conf'
	parser = WinApacheParser(basepath)
	parser.findNestedNodes(nodeList,filepath)
	#for mainNodes in nodeList:
	#	parser.findVirtualHosts(virtualHosts,mainNodes)
	#contents=[]
	#with open('C:/Apache24/conf/extra/httpd-ahssl.conf','r') as fp:
	#	contents = fp.readlines()
	#	indices = [i for i, s in enumerate(contents) if i>=158 and i<=171 and 'SSLCertificateFile' in s]
	#	contents.pop(indices[0])
	#	contents.insert(indices[0],"HLOO")
	
	#with open('C:/Apache24/conf/extra/httpd-ahssl.conf','w') as fp:
	#	fp.write("".join(contents))
	listenDirectives = set()
	for mainNodes in nodeList:
		parser.findListenDirectives(listenDirectives,mainNodes)
	
	listens = map(lambda x:x.content.strip(),listenDirectives)
	print(list(listens))

	#for vhosts in virtualHosts:
	#	print("VirtualHost :{0} File:{1} start:{2} end:{3}".format(vhosts.content,vhosts.filePath,vhosts.startLine,vhosts.endLine))
	#print("VirtualHosts found:{0}".format(len(virtualHosts)))
	
	#node = ApacheParser.parse(filepath)
	#print("nodeCount:{}".format(len(node.children[0].children)))
	#for child in node.children:
	#	if child.name.casefold() == "virtualhost".casefold():
	#		print("child:{0}".format(child.content))

	#for tagNode in ApacheParser.getNodesOfName("Include",node):
	#	print("Name:{2} Start:{0} End:{1} Content:{3}".format(tagNode.startLine,tagNode.endLine,tagNode.name,tagNode.content))
	




#for tagNode in ApacheParser.getNodesOfType(Type.TAG,node):
#	print("Name:{2} Start:{0} End:{1}".format(tagNode.startLine,tagNode.endLine,tagNode.name))
#for tagNode in ApacheParser.getNodesOfName("Include",node):
#	print("Name:{2} Start:{0} End:{1} Content:{3}".format(tagNode.startLine,tagNode.endLine,tagNode.name,tagNode.content))
#for tagNode in ApacheParser.getNodesOfType(Type.TAG,node):
#	print(re.match(directiveRegex,tagnode.content).group(2))
	