
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render


import scapy.all as scapy
from typing import Type
from mac_vendor_lookup import MacLookup
import argparse

from .forms import ScannerForm
import urllib
import cv2
import numpy as np
import ssl
import urllib.request
from .models import Scanner
import netifaces
import requests
from requests.exceptions import ConnectionError
import nmap
import vulners

@login_required
def scan_network(request):
    form = None
    if request.method == 'POST':
        form = ScannerForm(request.POST)
        if form.is_valid():
            # capture from gateway

            gateways = netifaces.gateways()
            gateway = gateways['default'][netifaces.AF_INET][0]
            
           
            # ip = form.cleaned_data["ipaddress"]
            ip=gateway+"/24"
            

            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            clients_list = []

           
            for element in answered_list:
                client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                clients_list.append(client_dict)
           
            # 



            print("IP\t\t\tMAC Address\n-----------------------------------------")
            
            
            for client in clients_list:
                
               
                # get vendor 
                ipaddress = client["ip"] 
                os_name =  ""

                
                # start get os 

                try:
                    nm = nmap.PortScanner()
                    scanner =  nm.scan(ipaddress, arguments="-O")
                    os_class =  scanner['scan'][ipaddress]['osmatch'][0]
                    os_name = os_class['name']
                except:
                    os_name = "Unknown"
                 


                # end get os 



                macaddress = client["mac"]
                vendor = ""
                vulners = "None"
                try:
                    vendor = MacLookup().lookup(str(macaddress))
                except:
                    vendor = "Unkown"

                # file is saved
                data = form.save(commit=False)
                data.ipaddress = ipaddress 
                data.vendor = vendor
                data.macaddress = macaddress
                data.vulners = vulners
                data.os_name = os_name

                # check if ip and mac exit before saving


                ipexist = Scanner.objects.filter(ipaddress=ipaddress).exists()
                if(not ipexist):
  
                    data.save()
            
                print(client["ip"] + "\t\t" + client["mac" ])

                

            if not clients_list:
                print("empty ips")
                messages.add_message(request, messages.ERROR, ' No New Device Found /Showing captured devices')
            else:
                messages.add_message(request, messages.INFO, ' Devices Found ')

            
            
            return HttpResponseRedirect('/scanner/history')
    else:
        form = ScannerForm()
    pass
    context = {
        
        'form': form , 
        'title': "Scan For devices"
        
    }   
    return render(request, 'scanner/scan.html',context)
@login_required
def display_history(request):
    
    scanners  = Scanner.objects.all()


    context = {
        'scanners': scanners, 
         'title': "History" 
    }

    # print(data_list)
    return render(request, 'scanner/history.html', context)

@login_required
def scan_vulnerabilities(request ,device_id=None):
    iotdevice = Scanner.objects.get(pk=device_id)
    vuln = []
    issues = []

    # check ipcamera vulnerability open port , weak passwrd  
    url = 'http://'+iotdevice.ipaddress+':8080/shot.jpg'
    
    try:
        r = requests.get(url,auth=('admin', 'admin123'))
        if(r.status_code == 200):
            vuln.append("weak_pass")

    except ConnectionError as e: 
        # no action here connection failure    
        print("error on this auth")

    
     
    # check ipcamera vulnerability open port no auth 
    
    try:
        r = requests.get(url)
        if(r.status_code == 200):
            vuln.append("open_port")
            vuln.append("no_pass")
            

    except ConnectionError as e: 
        # no action here connection failure    
        print("error ,skipped")

    # scan for platform 
    try:
        vulners_api = vulners.Vulners(api_key="64AUGCYS02Y3RWY84T2RXYA24SRDEAE1V0JU9X96GG92DTT6VN5EILKQJRE2CSDX")
        nm = nmap.PortScanner()
        scanner =  nm.scan(iotdevice.ipaddress, arguments="-O")
        os_class =  scanner['scan'][iotdevice.ipaddress]['osmatch'][0]

        # cpe 
        cpe = os_class['osclass'][0]['cpe'][0]
    
        print("cpe 1")
        print(os_class['osclass'][0]   )
        print("cpe 2")

        # "cpe:/o:microsoft:windows_10"
        # "cpe:/a:cybozu:garoon:4.2.1"

        print(cpe+":*")

        # cpe_results = vulners_api.cpeVulnerabilities("cpe:/o:microsoft:windows_10:*")
        cpe_results = vulners_api.cpeVulnerabilities(cpe+":*")
        cpe_exploit_list = cpe_results.get('exploit')
        vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
        # print("vulneralibity type_____"+vulnerabilities_list[0][0]['type'])
        # print(vulnerabilities_list[0][0]['title'])
        all_issues = vulnerabilities_list[0]
        issues = all_issues[:12]
        
    


        # print(os_class['osclass'][0])
            
    except:
       
        print("vulners error ")




    
    
          
    # pump in db 
    
    # convert to list
    iotdevice.vulners = ",".join(vuln)
    iotdevice.save()

   
    context = {
        'item': iotdevice, 
        'vulnerabilities':iotdevice.vulners.split(',') , 
        'title': "Vulnerability Scan" ,
        'issues':issues
    }

    for item in issues:
        print("bre______________________ak")
       
        print(item['cvelist'])
        print("bre______________________ak")

    # print(data_list)
    return render(request, 'scanner/check_vuln.html', context)

@login_required
def livecam(request ,device_id=None):
    iotdevice = Scanner.objects.get(pk=device_id)

    # start camera section_________________________________
           
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    url = 'http://'+iotdevice.ipaddress+':8080/shot.jpg'
    try:
        while True:
            imgResp = urllib.request.urlopen(url)
            imgNp = np.array(bytearray(imgResp.read()), dtype=np.uint8)
            img = cv2.imdecode(imgNp, -1)
            
            cv2.imshow(iotdevice.ipaddress+' Live Camera',cv2.resize(img,(600,400)))
            q = cv2.waitKey(1)
            if q == ord("q"):
                break
        cv2.destroyAllWindows()
    except:
        messages.add_message(request, messages.ERROR, 'Could not connect to source or session ended ')
        return HttpResponseRedirect('/scanner/history')

    # end camera section___________________________________


    return HttpResponseRedirect('/scanner/history')

@login_required
def view_recommendation(request ,cve_id =None):

    vulners_api = vulners.Vulners(api_key="64AUGCYS02Y3RWY84T2RXYA24SRDEAE1V0JU9X96GG92DTT6VN5EILKQJRE2CSDX")
    cve_data = vulners_api.document(cve_id)['affectedSoftware']
    print(cve_data)
    # newdata = cve_data.affectedSoftware
    # print(newdata)
    # for item in cve_data.affectedSoftware:
    #     print(item)


    context = {
        'data': cve_data, 
         'title': "Recommendation" 
    }
    return render(request, 'scanner/recommendation.html', context)

@login_required
def device_delete(request ,device_id=None):
    iotdevice = Scanner.objects.get(pk=device_id)
    iotdevice.delete()
    messages.add_message(request, messages.INFO, ' IOT device successfully deleted')
    return HttpResponseRedirect('/scanner/history')