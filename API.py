#!/usr/bin/env python
# coding:utf-8


from multiprocessing import Process, Queue, TimeoutError
from progress.bar import Bar
from termcolor import colored
import requests, json, fnmatch, os, time

class API:

	def __init__(self,ip):
		self.url='http://'+ip+'/api/v1.1/'
		self.endpoint=''
		self.result=''
		self.ip=ip

	def setEndpoint(self,endpoint):
		self.endpoint=endpoint


	def getResult(self):
		return self.result

	def sendRequest(self, requestType, files=None, jsonFile=None):

		if requestType == 'POST':
			self.result = json.dumps(requests.post(self.url+self.endpoint, files=files, json=jsonFile).json(), sort_keys=True, indent=4)
		elif requestType == 'GET':
			self.result = json.dumps(requests.get(self.url+self.endpoint).json(), sort_keys=True, indent=4)


class IRMA(API):
	def __init__(self):
		API.__init__(self,'172.16.1.30')
		self.scanId=''
		self.scanResult=list()

	def setScanId(self,data):
		self.scanId=str(data)

	def scans(self):
		self.setEndpoint('scans')
		self.sendRequest('POST')
		self.scanId=json.loads(self.result)['id']
		return self.getResult()

	def getListScans(self):
		self.setEndpoint('scans')
		self.sendRequest('GET')
		return self.getResult()

	def getScanDetails(self):
		self.setEndpoint('scans/'+self.scanId)
		self.sendRequest('GET')
		return self.getResult()	

	def launchScan(self):
		self.setEndpoint('scans/'+self.scanId+'/launch')
		self.sendRequest('POST',jsonFile={"force": True,"mimetype_filtering": True, "resubmit_files": True})
		return self.getResult()

	def cancelScan(self):
		self.setEndpoint('scans/'+self.scanId+'/cancel')
		self.sendRequest('POST')
		return self.getResult()

	def uploadFile(self,path):
		self.setEndpoint('scans/'+self.scanId+'/files')
		file={'file': open(path, 'rb')}
		self.sendRequest('POST',files=file)
		return self.getResult()

	def getScanResult(self):
		self.setEndpoint('scans/'+self.scanId+'/results')
		self.sendRequest('GET')
		print(self.getResult())
		for res in json.loads(self.result):
			self.scanResult.append(res['result_id'])
		return self.getResult()

	def getResults(self,resultId):
		self.setEndpoint('results/'+resultId)
		self.sendRequest('GET')
		return self.getResult()


class Scanner(IRMA):
	def __init__(self,path):
		IRMA.__init__(self)
		self.path=path
		self.listFile=list()

	def setListFile(self):
		self.listFile = [os.path.join(self.path, f)
			for self.path, dirnames, files in os.walk(self.path)
			for f in fnmatch.filter(files, '*.*')]

	def analysis(self):
		boolResult=False
		for result in json.loads(self.result)['results']:
			if result['status'] == 1:
				boolResult=True
				print(colored('The file '+str(result['name'])+' contains a virus', 'red'))
				print(colored('File Hash: ', 'red') +str(result['file_sha256']))
				print(colored('Result link: ', 'red')+ str('http://'+self.ip+'/results/') +str(result['result_id']))
		if boolResult == False:
			print(colored("No virus have been detected on the USB Key","green"))
	
	def run(self):
		self.scans()
		print("Scan link: http://172.16.1.30/scan/"+self.scanId)
		print("Number of files to analyze: " + str(len(self.listFile)))
		bar = Bar('Uploading files', max=len(self.listFile))
		for file in self.listFile:
			self.uploadFile(file)
			bar.next()
		bar.finish()

		processAnalyse=Process(target=self.launchScan)
		processAnalyse.daemon = True
		processAnalyse.start()
		time.sleep(2.5)
		scanStatus=json.loads(self.getScanDetails())
		status=scanStatus['probes_finished']
		end=scanStatus['probes_total']
		bar = Bar('Analysis of files', max=len(self.listFile)*scanStatus['results'][0]['probes_total'])
		
		while scanStatus['probes_finished']<scanStatus['probes_total']:
			scanStatus=json.loads(self.getScanDetails())
			if status < scanStatus['probes_finished']:
				for i in range(scanStatus['probes_finished']-status):
					bar.next()
				status=scanStatus['probes_finished']
			time.sleep(2)
		bar.finish()
		processAnalyse.join(1)
		processAnalyse.terminate()
		self.analysis()

#Example
#a=Scanner('Path of files to be scanned')
#a.setListFile()
#a.run()
