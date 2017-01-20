import argparse
from xml.etree import ElementTree
#pip install requests
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime
#pip install tzlocal
from tzlocal import get_localzone
import getpass
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
from subprocess import call
import winreg
import os

class ConnectionObject:
	def getServer(self):
		return self.__server
	def getPort(self):
		return self.__port
	def getToken(self):
		return self.__token
	def getVerify(self):
		return self.__verify
	def getNameSpace(self):
		return self.__namespace

	
	def setServer(self,server):
		self.__server = server
	def setPort(self,port):
		self.__port = port
	def setToken(self,token):
		self.__token = token
	def setVerify(self,verify):
		if not verify:
			requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
		self.__verify = verify
					
	
	def getLogonSession(self):
		return self.__logonsession
		
	def __init__(self, server, port,verify, version="latest",token=0):
		self.__server = server
		self.__port = port
		self.__token = token
		self.__verify = verify
		self.__version = version
		self.__namespace = "http://www.veeam.com/ent/v1.0"
		self.__tokenheader = "X-RestSvcSessionId"
		self.__logout = ""
		self.__logonsession = None
		
		if not verify:
			requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
		
		self.__session = requests.Session()

	
	def connstr(self,trailing=""):
		return "https://{server}:{port}/api/{trailing}".format(server=self.__server,port=self.__port,trailing=trailing)
	
	
	
	def request(self,method="GET",trailing="",data=None,params={},auth=None,href=""):
		uri = href
		if uri == "":
			uri = self.connstr(trailing)
			
		req = requests.Request(method,uri,data=data,params=params,auth=auth)
		prepped = req.prepare()
		
		if not self.__token == 0:
			prepped.headers[self.__tokenheader] = self.__token
		
		
		resp = self.__session.send(prepped,verify=self.__verify)
		
		return resp
		
	def updateNamespace(self,tag):
		m = re.match('\{.*\}', tag)
		self.__namespace = m.group(0) if m else ''
		
	def xpathfindall(self,root,what):
		xpath = ".//{ns}{what}".format(ns=self.__namespace,what=what)
		return root.findall(xpath)
		
	def authenticate(self,username,password):
		self.__token = 0
		resp = self.request()

		if resp.status_code == 200:
			#print(resp.content)
			root = ElementTree.fromstring(resp.content)
			self.updateNamespace(root.tag)

			apihref = ""
			lookfor = ".*[?]v[=]{v}".format(v=self.__version)
			
			#print(lookfor)
			for link in self.xpathfindall(root,"Link[@Type='LogonSession']"):
				href = link.attrib["Href"]
				testm = re.match(lookfor,href)
				if testm != None:
					apihref = href
					
			
			if apihref != "":
				session = self.request(method="POST",href=href,auth=HTTPBasicAuth(username,password))	
				if self.__tokenheader in session.headers:
					self.__token = session.headers[self.__tokenheader]
					
					root = ElementTree.fromstring(session.content)
					self.__logonsession = root
					
					
					for link in self.xpathfindall(root,"Link[@Rel='Delete']"):
						href = link.attrib["Href"]
						testm = re.match(".*/api/logonSessions/.*",href)
						if testm != None:
							self.__logout = href
					
			else:
				print("Could not find matching API")
			
		else:
			print("Is this an enterprise manager?")
		
		

	
	
	def logout(self):
		if self.__logout != "":
			resp = self.request(method="DELETE",href=self.__logout)
			#print(self.__logout)
			if resp.status_code == 204:
				print("Logged out")
			else:
				print("Could not logout ({code})".format(code=resp.status_code))
		else:
			print("Logout url was not set during login")

class VBRServer:
		def __init__(self, name,urn,href):
			self.name = name
			self.urn = urn
			self.href = href

class VBRJob:
		def __init__(self, name,urn,href,backupserverhref):
			self.name = name
			self.urn = urn	
			self.href = href
			self.backupserverhref = backupserverhref
			self.sessions = []
			self.lastsession = 0
			
class VBRSession:
		def __init__(self, name,urn,href,jobhref,endtimeutc,result):
			self.name = name
			self.urn = urn	
			self.href = href
			self.jobhref = jobhref
			self.endtimeutc = endtimeutc
			self.result = result
			
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-s","--server",default="localhost")
	parser.add_argument("-P","--port",default="9398", type=int)
	parser.add_argument("-u","--username",default="administrator")
	parser.add_argument("-p","--password",default=None)
	parser.add_argument("-i","--ignorecert",action='store_true')
	parser.add_argument("-v","--vbrconsole",default='C:\\Program Files\\Veeam\\Backup and Replication\\Console\\veeam.backup.shell.exe')
	parser.add_argument("action",default=["lsjob"],nargs=argparse.REMAINDER)

	
	parsed = parser.parse_args()	
	
	
	vbrconsole = parsed.vbrconsole
	if not os.path.isfile(vbrconsole):
		print("No valid exit to VBR Console (Not {0}), launching it will not work, supply alternate location with -v <pathto>\veeam.backup.shell.exe ".format(vbrconsole))
	
	
	password = parsed.password
	if password == None:
		password = getpass.getpass("Password:")
	
	co = ConnectionObject(parsed.server,parsed.port,(not parsed.ignorecert))
	co.authenticate(parsed.username,password)
	
	if co.getToken() != 0:
		print("Got connected")
		backupserverreq = co.request(trailing="backupservers")
		
		if backupserverreq.status_code < 400:
			backupservers = {}
			root = ElementTree.fromstring(backupserverreq.content)
			
			for b in co.xpathfindall(root,"Ref[@Type='BackupServerReference']"):
				backupservers[b.attrib["Href"]] = VBRServer(b.attrib["Name"],b.attrib["UID"],b.attrib["Href"])
			
			#for b in backupservers:
			#	print(backupservers[b].href)
			
			
			jobsreq = co.request(trailing="jobs")
			if jobsreq.status_code < 400:
				jobs = {}
				jobsarr = []
				root = ElementTree.fromstring(jobsreq.content)
				for j in co.xpathfindall(root,"Ref[@Type='JobReference']"):
					blink = co.xpathfindall(j,"Link[@Type='BackupServerReference']")[0]
					vbrj = VBRJob(j.attrib["Name"],j.attrib["UID"],j.attrib["Href"],blink.attrib["Href"])
					jobs[j.attrib["Href"]] = vbrj
					jobsarr.append(vbrj)
				#for j in jobs:
				#	print(jobs[j].name)
				
				
				sessreq = co.request(trailing="backupSessions",params={"format":"Entity"})
				if sessreq.status_code < 400:
					sessions = {}
					root = ElementTree.fromstring(sessreq.content)
					for s in co.xpathfindall(root,"BackupJobSession"):
						attr = s.attrib
						jlink = co.xpathfindall(s,"Link[@Type='JobReference']")[0].attrib["Href"]
						#python crappy time parsing fix so that it force utc
						ufind = co.xpathfindall(s,"EndTimeUTC")
						if len(ufind) > 0:
							endtimeutc = "{0}+0000".format(ufind[0].text)
						result = co.xpathfindall(s,"Result")[0].text
						
						vbrsess = VBRSession(attr["Name"],attr["UID"],attr["Href"],jlink,datetime.strptime(endtimeutc,"%Y-%m-%dT%H:%M:%S.%fZ%z"),result)
						sessions[attr["Href"]] = vbrsess
						
						if jlink in jobs:
							j = jobs[jlink]
							j.sessions.append(vbrsess)
							if j.lastsession == 0:
								j.lastsession = vbrsess
							elif j.lastsession.endtimeutc < vbrsess.endtimeutc:
								j.lastsession = vbrsess
					
					#for s in sessions:
					#	print(sessions[s].endtimeutc.astimezone(get_localzone()))
					

					jobsel = -1
					
					while jobsel != 'q':
						print("Detected Backup Jobs\n#########################")
						for j in range(len(jobsarr)):
							job = jobsarr[j]
							last = job.lastsession
							
							if last == 0:
								print("{j}) {n} NO SESSION FOUND".format(j=j,n=job.name))
							else:
								print("{j}) {n} {d} {s}".format(j=j,n=job.name,d=last.endtimeutc.astimezone(get_localzone()),s=last.result))
												
						jobsel = input("Job to inspect (q to exit): ")	
						
						if jobsel != 'q':
							jobselint = int(jobsel)
							
							if jobselint >= 0 and jobselint < len(jobsarr):
								job = jobsarr[jobselint]
								bs = backupservers[job.backupserverhref]
								
								dosel = -1
								while dosel != 'q':
									print("\n\nAction on {j}\n#########################".format(j=job.name))
									print("1) Start Job {0}".format(job.name))
									print("2) Launch VBR Console (Windows Authentication) {0}".format(bs.name))
									print("3) Launch VBR Console {0}".format(bs.name))
									print("4) Launch MSTSC to {0}".format(bs.name))
									print("q) Back to job menu")
									print("x) Back to job menu")
									dosel = input("Action :")
									
									if dosel == "1":
										jstartreq = co.request(href=job.href,method="POST",params={"action":"start"})
										if jstartreq.status_code < 400:
											print("Job started")
											#print(jstartreq.content)
										else:
											print("Something went wrong starting ({0})".format(jstartreq.status_code))
									elif dosel == "2":
										#"C:\Program Files\Veeam\Backup and Replication\Console\veeam.backup.shell.exe" –logon VeeamBackupServer:localhost:9392:current"
										constring = "VeeamBackupServer:{b}:9392:current".format(b=bs.name)
										call([vbrconsole,"-logon",constring])
									elif dosel == "3":
										constring = "VeeamBackupServer:{b}:9392:{d}\\administrator".format(b=bs.name,d=bs.name)
										print(constring)
										call([vbrconsole,"-logon",constring])
									elif dosel == "4":
										call(["mstsc","/v:{0}".format(bs.name)])
									elif dosel == "x":
										dosel = 'q'
										jobsel = 'q'
									
									

					
		co.logout()
	else:
		print("Not authenticated")