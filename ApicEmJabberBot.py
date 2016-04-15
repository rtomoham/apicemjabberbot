from jabberbot import JabberBot, botcmd
import datetime

import logging
logging.basicConfig()

import requests, json, sys
from ConfigParser import SafeConfigParser

# Disable invalid certificate warnings
#requests.packages.urllib3.disable_warnings()

import re

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

def getServiceTicket():
        ticket=None
        #specify the username and password which will be included in the data.  Replace 'xxxx' with
        #your username and password
        payload = {
                "username": APICEM_USERNAME,
                "password": APICEM_PASSWORD
        }
        
        #Content type must be included in the header
        header = {"content-type": "application/json"}
        
        #Format the payload to JSON and add to the data.  Include the header in the call. 
        #SSL certification is turned off, but should be active in production environments
        response = requests.post(
                url = TICKET_URL,
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

#Make the REST call using the service ticket, command, http url, data for the body (if any)
def doRestCall(command, request_URL, aData=None):
        response_json = None
        payload = None
        try:
        
                #if data for the body is passed in put into JSON format for the payload
                if(aData != None):
                        payload=json.dumps(aData)

                #add the service ticket and content type to the header
                header = {
                        "X-Auth-Token": getServiceTicket(),
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

def doRestCallJson(command, request_URL, aData=None):
        return doRestCall(command, request_URL, aData).json()

def getDeviceIDs():
        url = CONTROLLER_URL + 'api/v1/network-device'
        
        response = doRestCall(GET, url)
                
        binary = response.content
        output = json.loads(binary)
                
        deviceIDs = []
        for device in output['response']:
                deviceIDs.append(device['id'])
                        
        return deviceIDs
                
def getRoles():
        url = CONTROLLER_URL + 'api/v1/user/role'

        response = doRestCall(GET, url)

        binary = response.content
        output = json.loads(binary)
        
        roles = []
        for role in output['response']:
                roles.append(role['role']) 

        return roles
        
def getRolesString():
        roles = getRoles()
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

def getUsers():
        url = CONTROLLER_URL + 'api/v1/user'
        
        response = doRestCall(GET, url)

#        print "getUsers response: " + response.text + "\n"
        
        binary = response.content
        output = json.loads(binary)
        
        users = []
        for user in output['response']:
                users.append(user['username'])
#        print "Users: " + str(len(users))
        return users
        
def createserviceticket():
        response = requests.post(
                url = CONTROLLER_URL + 'api/v1/ticket',
                headers={
                        "Content-Type": "application/json",
                },
                verify=False,
                data=json.dumps({
                        "username": APICEM_USERNAME,
                        "password": APICEM_PASSWORD
                })
        )
        output = ('Response HTTP Response Body: {content}'.format(content=response.content))
        match_service_ticket = re.search('serviceTicket":"(.*cas)', output, flags=0)
        service_ticket = match_service_ticket.group(1)
        return service_ticket

def getresponse(url):
        response = requests.get(
                url,
                headers={
                        "X-Auth-Token": createserviceticket(),
                        "Content-Type":"application/json"
                },
                verify=False
        )
        return response

def postresponse(url):
        response = requests.post(
                url,
                headers={
                        "X-Auth-Token": createserviceticket(),
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

class ApicEmJabberBot(JabberBot):

#        @botcmd
#        def test(self, mess, args):
#                """test"""
#                result = args.split()
#                return result[0]
                
        @botcmd
        def echo(self, mess, args):
                """echo {args}"""
                return args
                
        @botcmd
        def adduser(self, mess, args):
                """Add a user w/ {username} {password} {scope} {role}, for instance 'adduser jdoe Cisco123$ ALL ROLE_ADMIN'"""
                url = CONTROLLER_URL + 'api/v1/user'
                arguments = args.split()

                if (2 == len(arguments)) or (4 == len(arguments)):

                        if arguments[0] in getUsers():
                                return "Error: user " + arguments[0] + " already exists. Choose a different user name."

                        if 2 == len(arguments):
                                scope = "ALL"
                                role = "ROLE_ADMIN"
                        
                        elif 4 == len(arguments):
                                if arguments[2] <> "ALL":
                                        return "Error: scope '" + arguments[2] + "' not supported. Scope must be 'ALL'."
                        
                                roles = getRoles()
                                if arguments[3] not in roles:
                                        outputString = "Error: role '" + arguments[3] + "' no allowed. Role must be in "
                                        outputString += getRolesString() + ", e.g., '" + roles[0] + "'."
                                        return outputString
                                        
                                scope = arguments[2]
                                role = arguments[3]
                                
                        data = ({
                                "username": arguments[0],
                                "password": arguments[1],
                                "authorization": [{
                                        "scope": scope,
                                        "role": role
                                }]
                        })
                        

                        response = doRestCall(POST, url, data)
                        if "No data returned!" == response:
                                return "Error: password '" + arguments[1] + "' not compliant with security policy. Use a stronger password."
                                        
                        response_json = response.json()
                        
                        return json.dumps(
                                response_json,
                                indent=4,
                                separators=(',', ':')
                        )
                else:
                        roles = getRoles()
                        print "len(roles): " + str(len(roles))
                        outputString = "adduser requires four arguments: {username} {password} {scope: (ALL)} {role: "
                        outputString += getRolesString()
                        outputString += "},\ne.g. 'adduser jdoe Cisco123$ ALL ROLE_OBSERVER'."
                        return outputString
                        
        @botcmd
        def deluser(self, mess, args):
                """Delete user w/ {username}"""
                if args == "admin":
                        return "Admin user cannot be deleted through xmpp!"
                else:
                        url = CONTROLLER_URL + 'api/v1/user/' + args
                        data = ({
                                "username" : args
                        })
                        response_json = doRestCallJson(DELETE, url, data)
                        return json.dumps(
                                response_json,
                                indent=4,
                                separators=(',', ':')
                        )                       

        @botcmd
        def getdevices_detail(self, mess, args):
                """Lists all network devices"""
                url = CONTROLLER_URL + 'api/v1/network-device'
        
                response = getresponse(url)
                response_json = response.json()
                return "Devices = " + json.dumps(
                        response_json,
                        indent=4,
                        separators=(',', ':')
                )

        @botcmd
        def getdevices(self, mess, args):
                """Lists all network devices -- brief"""
                url = CONTROLLER_URL + 'api/v1/network-device'
        
                response = getresponse(url)
                
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
                        
                if args not in getDeviceIDs():
                        return "Error: device with device-id '" + args + "' not found."
                        
                url = CONTROLLER_URL + 'api/v1/network-device/' + args
                        
                response = getresponse(url)
                response_json = response.json()

                ticket = None
                response_json = doRestCallJson(GET, url)

                return "Device details = " + json.dumps(
                        response_json,
                        indent=4,
                        separators=(',', ':')
                )
                
        @botcmd
        def getroles(self, mess, args):
                roles = getRoles()
                outputString = "Roles: "
                for role in roles:
                        outputString += "\n !---> " + role
                return outputString

#        @botcmd
#        def network_device_config(self, mess, args):
#                """Returns the config of network device with {id}"""
#
#                url = controller_url + 'api/v1/network-device/' + args + '/config'
#        
#                response = requests.get(
#                        url,
#                        headers={
#                                "X-Auth-Token": createserviceticket(),
#                                "Content-Type":"application/json"
#                        },
#                        verify=False
#                )
#                response_json = response.json()
#                return "Device config = " + json.dumps(
#                        response_json,
#                        indent=4,
#                        separators=(',', ':')
#                )

        @botcmd
        def getusers(self, mess, args):
                """Returns all users"""

                url = CONTROLLER_URL + 'api/v1/user'
        
                response = getresponse(url)
#                response_json = response.json()
#                return "Users = " + json.dumps(
#                        response_json,
#                        indent=4,
#                        separators=(',', ':')
#                )

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

                url = CONTROLLER_URL + 'api/v1/user/status/' + args
        
                response = getresponse(url)
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
                
        @botcmd
        def topology(self, mess, args):
                """Returns the topology"""

                url = CONTROLLER_URL + 'api/v1/topology/physical-topology'
        
                response = getresponse(url)
                response_json = response.json()
                return "Topology = " + json.dumps(
                        response_json,
                        indent=4,
                        separators=(',', ':')
                )
                
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
                                                                           

																		   
																		   
# Define constants
GET = "get"
POST = "post"
DELETE = "delete"

CONTROLLER_IP = read_config_file('apicem', 'CONTROLLER_iP')
CONTROLLER_PORT = read_config_file('apicem', 'CONTROLLER_PORT')
CONTROLLER_URL = "https://" + CONTROLLER_IP + ":" + CONTROLLER_PORT + "/"
TICKET_URL = CONTROLLER_URL + "api/v1/ticket"
APICEM_USERNAME = read_config_file('apicem', 'APICEM_USERNAME')
APICEM_PASSWORD = read_config_file('apicem', 'APICEM_PASSWORD')

XMPP_USERNAME = read_config_file('xmpp', 'XMPP_USERNAME')
XMPP_PASSWORD = read_config_file('xmpp', 'XMPP_PASSWORD')
							
bot = ApicEmJabberBot(XMPP_USERNAME, XMPP_PASSWORD)
#bot.presence(chat)
bot.serve_forever()
                                                                                                                