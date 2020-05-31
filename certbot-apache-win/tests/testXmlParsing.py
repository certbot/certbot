#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
from enum import Enum

commentRegex = '#.*'
directiveRegex = '([^\s]+)\s*(.+)'
sectionOpenRegex = '<([^/\s>]+)\s*([^>]+)?>'
sectionCloseRegex = '</([^\s>]+)\s*>'
basepath = 'c:/Apache24/'

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


class ApacheParser:

	def getNodesOfType(nodeType,currentNode):
		matchingNodes = list()
		for node in currentNode.children:
			if(node.nodeType == nodeType):
				matchingNodes.append(node)
				
		return matchingNodes
	
	def getNodesOfName(name,currentNode):
		matchingNodes = list()
		for node in currentNode.children:
			if(node.name == name):
				matchingNodes.append(node)
				
		return matchingNodes

	def parse(filePath):
		with open(filePath) as fp:
			currentNode = ConfigNode.createRootNode()
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

def findNestedNodes(nodeList,filepath):
	node = ApacheParser.parse(filepath)
	nodeList.add(node)
	for directiveNode in ApacheParser.getNodesOfName("Include",node):
		findNestedNodes(nodeList,basepath+directiveNode.content)
	for tagNode in ApacheParser.getNodesOfType(Type.TAG,node):
		if len(tagNode.children)>0:
			for directiveNode in ApacheParser.getNodesOfName("Include",tagNode):
				findNestedNodes(nodeList,basepath+directiveNode.content)

def findVirtualHosts(virtualHosts,currentNode):
	for node in currentNode.children:
			if(node.nodeType == Type.TAG and node.name.casefold() == "virtualhost".casefold()):
				virtualHosts.add(node)
		


if __name__ == '__main__':
	nodeList = set()
	virtualHosts = set()
	filepath = basepath+'/conf/extra/httpdtest.conf'
	findNestedNodes(nodeList,filepath)
	for mainNodes in nodeList:
		findVirtualHosts(virtualHosts,mainNodes)
	
	for vhosts in virtualHosts:
		print("VirtualHost :{0} File:{1} start:{2} end:{3}".format(vhosts.content,vhosts.filePath,vhosts.startLine,vhosts.endLine))
		for child in vhosts.children:
			print("children:{0}".format(child.name))
	
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
	