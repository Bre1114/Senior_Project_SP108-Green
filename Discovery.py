#Names:
# Brenden Toussant
#
#
#

#Push the entire REPO into the organization before prototype demonstration

import socket
from xmlrpc.client import Boolean

import nmap #Imports nmap library, allowing access to nmap functions
#!!!Figure out how to set up nmap to function and form ASM for our environment

#Adapt to be automated for automatic asset discovery
def asset_discovery(): #Scans the
    print("Automatic Asset Discovery")
    hostname = socket.gethostname()
    targetIPAddr = socket.gethostbyname(hostname)
    nm = nmap.PortScanner() #Intializes the port scanner
    nm.scan (targetIPAddr,'22-446') #('IP of local host','Range of port numbers')
    #Figure out why it doesn't seem to work with my actual IP address and only the value in the IPAddr variable
    nm.command_line()
    nm.scaninfo()

    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
                lport = nm[host][proto].keys()
                for port in lport:
                    print('Port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))


print("Testing Code")
print("1. Asset Discovery")

asset_discovery()