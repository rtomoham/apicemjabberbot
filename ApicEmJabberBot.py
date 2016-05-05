from jabberbot import JabberBot, botcmd
import datetime

import logging
logging.basicConfig()

import requests, json, sys
from ConfigParser import SafeConfigParser

# Disable invalid certificate warnings
#requests.packages.urllib3.disable_warnings()

import re

# Helper function to grab config data from config.conf
def read_config_file(section, option):
	config = SafeConfigParser()
	config.read('config.conf')
	try:
		value = config.get(section, option)
	except Exception, e:
		logging.error('Error reading config.conf file!')
		logging.error(e)
		sys.exit(1)
	return value

class ApicEmJabberBot(JabberBot):

	# Additional initialization (beyond the JabberBot initialization, which takes care of the XMPP connection)
	def init(self):
        # PRE:	True
        # POST:	APIC-EM Controller details have been read from config.conf (IP address, port number, ticket url, username and password

		self._CONTROLLER_IP = read_config_file(SECTION_APIC_EM, 'CONTROLLER_IP')
		self._CONTROLLER_PORT = read_config_file(SECTION_APIC_EM, 'CONTROLLER_PORT')
		self._CONTROLLER_URL = "https://" + self._CONTROLLER_IP + ":" + self._CONTROLLER_PORT + "/"
		self._TICKET_URL = self._CONTROLLER_URL + "api/v1/ticket"
		self._APICEM_USERNAME = read_config_file(SECTION_APIC_EM, 'APICEM_USERNAME')
		self._APICEM_PASSWORD = read_config_file(SECTION_APIC_EM, 'APICEM_PASSWORD')

#        @botcmd
#        def test(self, mess, args):
#                """test"""
#                result = args.split()
#                return result[0]
                
        # All bot commands are preceded by @botcmd
        # These commands will be listed when asking the bot "help"

	@botcmd
	def echo(self, mess, args):
			"""echo {args}"""
			return args
			
	@botcmd
	def adduser(self, mess, args):
		"""Add a user w/ {username} {password} {scope} {role}, for instance 'adduser jdoe Cisco123$ ALL ROLE_ADMIN', defaults to scope == ALL and role == ROLE_ADMIN"""
		url = self._CONTROLLER_URL + 'api/v1/user'
		arguments = args.split()

		if (2 == len(arguments)) or (4 == len(arguments)):

			if arguments[0] in self.getUsers():
				return "Error: user " + arguments[0] + " already exists. Choose a different user name."

			if 2 == len(arguments):
			        # Set default scope and role, since only username and password were provided
				scope = "ALL"
				role = "ROLE_ADMIN"
			
			elif 4 == len(arguments):
				if arguments[2] <> "ALL":
				# If scope provided, it must be "ALL"
					return "Error: scope '" + arguments[2] + "' not supported. Scope must be 'ALL'."
		
				roles = self.getRoles()
				if arguments[3] not in roles:
				        # If role provided, it must be an existing role
					outputString = "Error: role '" + arguments[3] + "' no allowed. Role must be in "
					outputString += self.getRolesString() + ", e.g., '" + roles[0] + "'."
					return outputString
						
				scope = arguments[2]
				role = arguments[3]
			
			# Succesfully passed all the sanity checks of this adduser request		
			data = ({
				"username": arguments[0],
				"password": arguments[1],
				"authorization": [{
					"scope": scope,
					"role": role
				}]
			})

                        # Perform the actual rest call
			response = self.doRestCall(POST, url, data)
			if "No data returned!" == response:
			        # Oops, the password was not accepted by APIC-EM
				return "Error: password '" + arguments[1] + "' not compliant with security policy. Use a stronger password."
			
			response_json = response.json()
			
			return json.dumps(
				response_json,
				indent=4,
				separators=(',', ':')
			)
		else:
		        # The user did not provide the right amount of arguments (should provide 2 or 4 arguments)
			roles = self.getRoles()
			print "len(roles): " + str(len(roles))
			outputString = "adduser requires four arguments: {username} {password} {scope: (ALL)} {role: "
			outputString += self.getRolesString()
			outputString += "},\ne.g. 'adduser jdoe Cisco123$ ALL ROLE_OBSERVER'."
			return outputString
					
	@botcmd
	def deluser(self, mess, args):
		"""Delete user w/ {username}"""
		if args == "admin":
			return "Admin user cannot be deleted through xmpp!"
		else:
			url = self._CONTROLLER_URL + 'api/v1/user/' + args
			data = ({
				"username" : args
			})
			response_json = self.doRestCallJson(DELETE, url, data)
			return json.dumps(
				response_json,
				indent=4,
				separators=(',', ':')
			)                       

	@botcmd
	def getdevices_detail(self, mess, args):
		"""Lists all network devices"""
		url = self._CONTROLLER_URL + 'api/v1/network-device'

		response = self.getresponse(url)
		response_json = response.json()
		return "Devices = " + json.dumps(
			response_json,
			indent=4,
			separators=(',', ':')
		)

	@botcmd
	def getdevices(self, mess, args):
		"""Lists all network devices -- brief"""
		url = self._CONTROLLER_URL + 'api/v1/network-device'

		response = self.getresponse(url)
		
		binary = response.content
		output = json.loads(binary)
		
		outputstring = "Devices brief:"
		for device in output['response']:
			outputstring += "\nDevice id: " 
			outputstring += device['id']
			outputstring += "\n |---> hostname:     "
			outputstring += device['hostname']
			outputstring += "\n |---> type:         "
			outputstring += device['type']
			outputstring += "\n |---> locationName: "
			outputstring += device['locationName']
				
		return outputstring

	@botcmd
	def getdevice(self, mess, args):
		"""Lists details about the network device with {id}"""
		
		if args == "":
			return "Error: no device-id provided."
				
		if args not in self.getDeviceIDs():
			return "Error: device with device-id '" + args + "' not found."
				
		url = self._CONTROLLER_URL + 'api/v1/network-device/' + args
				
		response = self.getresponse(url)
		response_json = response.json()

		ticket = None
		response_json = self.doRestCallJson(GET, url)

		return "Device details = " + json.dumps(
			response_json,
			indent=4,
			separators=(',', ':')
		)
			
	@botcmd
	def getroles(self, mess, args):
		roles = self.getRoles()
		outputString = "Roles: "
		for role in roles:
			outputString += "\n !---> " + role
		return outputString

	@botcmd
	def getusers(self, mess, args):
		"""Returns all users"""

		url = self._CONTROLLER_URL + 'api/v1/user'

		response = self.getresponse(url)

		binary = response.content
		output = json.loads(binary)
		
		outputstring = "Users:"
		for user in output['response']:
			outputstring += "\nUsername: " 
			outputstring += user['username']
			for authorization in user['authorization']:
				outputstring += "\n |---> scope:        "
				outputstring += authorization['scope']
				outputstring += "\n |---> role:         "
				outputstring += authorization['role']
				
		return outputstring
			
	@botcmd
	def getuserstatus(self, mess, args):
		"""Returns the user with {username}'s status"""

		url = self._CONTROLLER_URL + 'api/v1/user/status/' + args

		response = self.getresponse(url)
		response_json = response.json()
		return "User " + args + "'s status = " + json.dumps(
			response_json,
			indent=4,
			separators=(',', ':')
		)
			
	@botcmd
	def hello(self, mess, args):
		"""Say hello to ApicEmJabberBot"""
		return "Hello " + mess.getFrom().getStripped() + ", my name is ApicEmJabberBot.\nI'm your xmppp interface to https://sandboxapic.cisco.com, a public APIC-EM on Cisco's devnet.\nFor help, just say 'help'.\nHave a nice day!"
			
#	@botcmd
#	def topology(self, mess, args):
#		"""Returns the topology"""
#
#		url = self._CONTROLLER_URL + 'api/v1/topology/physical-topology'
#
#		response = self.getresponse(url)
#		response_json = response.json()
#		return "Topology = " + json.dumps(
#			response_json,
#			indent=4,
#			separators=(',', ':')
#		)
			
	@botcmd
	def serverinfo( self, mess, args):
		"""Displays information about the server"""
		version = open('/proc/version').read().strip()
		loadavg = open('/proc/loadavg').read().strip()
		
		return '%snn%s' % ( version, loadavg, )
			
	@botcmd
	def time( self, mess, args):
		"""Displays current server time"""
		return str(datetime.datetime.now())
			
	@botcmd
	def whoami(self, mess, args):
		"""Tells you your username"""
		return mess.getFrom().getStripped()

    # End of ApicEmJabberBot commands
        
    # Begin of ApicEmJabberBot helper functions
        
    # Returns the users configured on APIC-EM
	def getUsers(self):
	    # PRE:	True
	    # POST: getUsers == list of user names
		url = self._CONTROLLER_URL + 'api/v1/user'
		
		response = self.doRestCall(GET, url)

		binary = response.content
		output = json.loads(binary)
		
		users = []
		for user in output['response']:
			users.append(user['username'])

		return users
		
    # Returns all the device id's known to APIC-EM
	def getDeviceIDs(self):
	    # PRE:	True
	    # POST:	getDeviceIDs == list of device id's on APIC-EM
		url = self._CONTROLLER_URL + 'api/v1/network-device'
		
		response = self.doRestCall(GET, url)
				
		binary = response.content
		output = json.loads(binary)
				
		deviceIDs = []
		for device in output['response']:
			deviceIDs.append(device['id'])
						
		return deviceIDs
	
	# Returns all the roles on APIC-EM			
	def getRoles(self):
	    # PRE:	True
	    # POST:	getRoles == list roles on APIC-EM
		url = self._CONTROLLER_URL + 'api/v1/user/role'

		response = self.doRestCall(GET, url)

		binary = response.content
		output = json.loads(binary)
		
		roles = []
		for role in output['response']:
			roles.append(role['role']) 

		return roles
	
	# Returns a formatted string containing all the roles on APIC-EM	
	def getRolesString(self):
	    # PRE:	True
	    # POST:	getRolesString == formatted string containing all roles (separated by '|')
		roles = self.getRoles()
		outputString = "("
		if 0 < len(roles):
			outputString += roles[0]
			i = 1
			while i < len(roles):
				outputString += "|"
				outputString += roles[i]
				i += 1
		outputString += ")"
		return outputString

	# Returns a service ticket which proves successful authentication
	def getServiceTicket(self):
	    # PRE:	self._APICEM_USERNAME and self._APICEM_PASSWORD are valid admin credentials
	    # POST: getServiceTicket == authenticated service ticket
	        
		ticket=None
		#specify the username and password which will be included in the data.  Replace 'xxxx' with
		#your username and password
		payload = {
			"username": self._APICEM_USERNAME,
			"password": self._APICEM_PASSWORD
		}
		
		#Content type must be included in the header
		header = {"content-type": "application/json"}
		
		#Format the payload to JSON and add to the data.  Include the header in the call. 
		#SSL certification is turned off, but should be active in production environments
		response = requests.post(
			url = self._TICKET_URL,
			headers = header,
			verify = False,
			data = json.dumps(payload)
		)

		#Check if a response was received. If not, print an error message.
		if(not response):
			print ("No data returned!")
		else:
			#Data received.  Get the ticket and print to screen.
			r_json = response.json()
			ticket = r_json["response"]["serviceTicket"]
			print ("ticket: ", ticket)
			return ticket
			
    # Predecessor to getServiceTicket. Not yet fully deprecated -- to be decommissioned
	def createserviceticket(self):
		response = requests.post(
			url = self._CONTROLLER_URL + 'api/v1/ticket',
			headers={
					"Content-Type": "application/json",
			},
			verify=False,
			data=json.dumps({
					"username": self._APICEM_USERNAME,
					"password": self._APICEM_PASSWORD
			})
		)
		output = ('Response HTTP Response Body: {content}'.format(content=response.content))
		match_service_ticket = re.search('serviceTicket":"(.*cas)', output, flags=0)
		service_ticket = match_service_ticket.group(1)
		return service_ticket

	#Make the REST call using the service ticket, command, http url, data for the body (if any)
	def doRestCall(self, command, request_URL, aData=None):
		response_json = None
		payload = None
		try:
			#if data for the body is passed in put into JSON format for the payload
			if(aData != None):
				payload=json.dumps(aData)

			#add the service ticket and content type to the header
			header = {
				"X-Auth-Token": self.getServiceTicket(),
				"content-type" : "application/json"
			}
			if(command==GET):
				r = requests.get(
					url = request_URL, 
					headers = header, 
					verify = False,
					data = payload 
				)
			elif(command==POST):
				r = requests.post(
					url = request_URL, 
					headers = header, 
					verify = False,
					data = payload 
				)
			elif(command==DELETE):
				print DELETE
				r = requests.delete(
					url = request_URL, 
					headers = header, 
					verify = False,
					data = payload 
				)
			else:
				#if the command is not GET, POST or DELETE we don't handle it.
				print ("Unknown command!")
				return "Unknown command!"

			#if no data is returned print a message; otherwise print data to the screen
			print r
			if(not r):
				print("No data returned!")
				return "No data returned!"
			else:
				print ("Returned status code: %d" % r.status_code)
		
	#                        #put into dictionary format
	#                        response_json = r.json()
				print(r)
				return r
		except:
			err = sys.exc_info()[0]
			msg_det = sys.exc_info()[1]
			print( "Error: %s  Details: %s StackTrace: %s" % (err,msg_det,traceback.format_exc()))
			return "Error: %s  Details: %s StackTrace: %s" % (err,msg_det,traceback.format_exc())

	# Performs the rest call and returns json
	def doRestCallJson(self, command, request_URL, aData=None):
	    # PRE:	command in [GET, POST, DELETE]
	    # POST:	json encoded reponse to calling request_URL
		return self.doRestCall(command, request_URL, aData).json()
		
    # Performs a GET and returns the response
	def getresponse(self, url):
		response = requests.get(
			url,
			headers={
				"X-Auth-Token": self.createserviceticket(),
				"Content-Type":"application/json"
			},
			verify=False
		)
		return response

    # Performs a POST and returns the response
	def postresponse(self, url):
		response = requests.post(
			url,
			headers={
				"X-Auth-Token": self.createserviceticket(),
				"Content-Type":"application/json"
			},
			data=({
				"username": "test",
				"password": "C1sco123",
				"authorization": [{
					"scope": "ALL",
					"role": "ROLE_OBSERVER"
				}]
			}),
			verify=False
		)
		return response

# End of class ApicEmJabberBot

# Start of main code			

# Define constants
GET = "get"
POST = "post"
DELETE = "delete"
SECTION_APIC_EM = 'apic-em'
SECTION_XMPP = 'xmpp'
XMPP_USERNAME = read_config_file(SECTION_XMPP, 'XMPP_USERNAME')
XMPP_PASSWORD = read_config_file(SECTION_XMPP, 'XMPP_PASSWORD')
			
bot = ApicEmJabberBot(XMPP_USERNAME, XMPP_PASSWORD)
bot.init()
#bot.presence(chat)
bot.serve_forever()
                                                                                                                