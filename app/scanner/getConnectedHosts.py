from threading import *
from socket import *
import optparse
from subprocess import call
from xml.dom import minidom
import os
import socket
import math
import sys
from datetime import datetime
import nmap

def getActiveHosts():
    try:
        intialIp = tuple(socket.gethostbyname_ex(socket.gethostname()))
        list = intialIp[2]
        intialIp = list[1]
        broadcastIp = intialIp[:intialIp .rfind(".")] + "." + "1/24"
        call(["nmap", "-v", "-sn", broadcastIp, "-oX", "output.xml"])
        archivoXML = minidom.parse("output.xml")
        listaDirecciones = archivoXML.getElementsByTagName("host")
        resultDic = []
        for s in listaDirecciones:
            if(s.getElementsByTagName("status")[0].attributes["state"].value == "up"):

                if(s.getElementsByTagName("address")[0].attributes["addr"].value != intialIp):

                    IPAddress = s.getElementsByTagName(
                        "address")[0].attributes["addr"].value
                    MACAddress = s.getElementsByTagName(
                        "address")[1].attributes["addr"].value
                    try:
                        vendor = s.getElementsByTagName(
                            "address")[1].attributes["vendor"].value
                    except:
                        vendor = "unknown"
                    resultDic.append(
                        {"ipAddress": IPAddress, "macAddress": MACAddress, "vendor": vendor})
                    # print(resultDic)
        return resultDic
    except:
        print("u are not on any network")

# def getOpenports(target):
#     try:
#         listOfPorts = []
        # will scan ports between 1 to 65,535
#         for port in range(1, 535):
#             s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             socket.setdefaulttimeout(1)
#             # returns an error indicator
#             result = s.connect_ex((target, port))
#             if result == 0:
#                 print("Port {} is open".format(port))
#                 listOfPorts.append({"open port": port})
#                 s.close()

#         print(listOfPorts)
#         return listOfPorts
#     except:
#         print("error")

# getOpenports("192.168.43.1")

# from typing import Protocol
# from getConnectedHosts import getActiveHosts
# from subprocess import call
# from xml.dom import minidom
# import os
# import socket
# import math


# def getOpenports():
#     # re = getActiveHosts()

#     # for d in re:

#         ip = "192.168.43.1"

#         call(["nmap","-vv","-n","-sS","-O", "-p", "21-1434", "-sV", ip, "-oX", "result1.xml"])
#         archivoXML = minidom.parse("result1.xml")
#         listDevices = archivoXML.getElementsByTagName("host")

#         listPort = []
#         print()
#         for host in listDevices:
#             try:
#                 hostname = host.getElementsByTagName(
#                     "address")[1].attributes["vendor"].value
#             except:
#                 hostname = host.getElementsByTagName(
#                     "address")[0].attributes["addr"].value

#             for port in host.getElementsByTagName("ports"):
#                 try:
#                     portNum = port.getElementsByTagName(
#                         "port")[0].attributes["portid"].value
#                     portstate = port.getElementsByTagName(
#                         "state")[0].attributes["state"].value
#                     protocol = port.getElementsByTagName(
#                         "port")[0].attributes["protocol"].value
#                     service = port.getElementsByTagName(
#                         "service")[0].attributes["product"].value
#                     os = port.getElementsByTagName(
#                         "osmatch")[0].attributes["name"].value  
#                     listPort.append(
#                         {"Port": portNum, "state": portstate, "Protocol": protocol, 
#                         "Service": service, "OS":os})
#                     print(hostname)
#                     print(listPort)
#                 except:
#                     print(hostname)
#                     print("all ports closed")
#             return listPort

# def getPorts(target):
#     portList = [21,22,25,53,80,110,443]
#     for port in portList:
#         print(target)
#         # nmScan = nmap.PortScanner()
#         # nmScan.scan(target, port)
#         # state=nmScan[target]['tcp'][int(port)]['state']
#         # print (" [*] " + target + " tcp/"+port +" "+state)
#         socket.setdefaulttimeout(2)
#         s = socket.socket()
#         s.connect((target,port))

   
#         # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         # socket.setdefaulttimeout(1)
#         # s.connect_ex((target, port))
#         banner = s.recv(1024)
#         if banner:
#                 print ('[+] ' + target + ': ' + banner)
#                 if 'FreeFloat Ftp Server (Version 1.00)' in banner:
#                     print ('[+] FreeFloat FTP Server is vulnerable.')
#                 elif '3Com 3CDaemon FTP Server Version 2.0' in banner:
#                     print ('[+] 3CDaemon FTP Server is vulnerable.')
#                 elif 'Ability Server 2.34' in banner:
#                     print ('[+] Ability FTP Server is vulnerable.')
#                 elif 'Sami FTP Server 2.0.2' in banner:
#                     print ('[+] Sami FTP Server is vulnerable.')
#                 else:
#                     print ('[-] FTP Server is not vulnerable.')
#     return
# getPorts("192.168.43.1")


 
