#!/usr/bin/env python
import scapy.all as scapy
import subprocess
import sys
import argparse
import platform
import time

def get_arguments(): #taking input as arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="enter the network interface")
    (arguments)= parser.parse_args()
    if not arguments.interface:
        parser.error("please specify the network interface")
    else:
        return arguments

def get_mac(ip): #getting mac address from an ip

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def sniff(interface): #monitoring network
    
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

    
def process_sniffed_packet(packet): #finding the hack
        
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac=packet[scapy.ARP].hwsrc
            #router_ip = packet[scapy.ARP].psrc
            #own_ip = packet[scapy.ARP].pdst
                             
            if(real_mac != response_mac):
                print("\t\t"+"\033[31m" + "[+]System is hacked!!\t\t")
                print("\033[39m" + "[+]Disconnecting network ")
                os_name = getting_platform()
                cutting_network_connection(arguments.interface,os_name)
                sys.exit()

        except IndexError:
            pass



def cutting_network_connection(interface,os): #cutting the network
    if(os == "Linux"):
        subprocess.call("ifconfig " + interface +  " down", shell=True)
        print("[-]Someone is monitoring your network.Your connection will restored in seconds")
        time.sleep(15)
        restore_network(interface,os)

    elif(os == "Windows"):
        subprocess.call("netsh interface set interface " + interface + " disable", shell=True)
        print("[-]Someone is monitoring your network Your connection will restored in seconds")
        time.sleep(15)
        restore_network(interface,os)

def getting_platform(): #getting operating system name
    os = platform.system()
    return os

def restore_network(interface,os): #restoring network
    if(os == "Linux"):
        subprocess.call("ifconfig " + interface +  " up", shell=True)
        print("[+]Restored Connection.")
        print("[+]If you still be victimed by the attack then network will be disconnected again")
        
    
    elif(os == "Windows"):
        subprocess.call("netsh interface set interface " + interface + " enable", shell=True)
        print("[+]Restored Connection.")
        print("[+]If you still be victimed by the attack then network will be disconnected again")
       
    sniff(interface)




arguments = get_arguments()

      
sniff(arguments.interface)



