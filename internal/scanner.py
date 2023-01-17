from scapy.all import *
import netifaces
import binascii
import threading
from netaddr import *
import time
import json
import os


def get_prefixes(pfxs):
    fname = './pfxs.json'
    if not os.path.isfile(fname):
        with open(fname, mode='w') as f:
            f.write(json.dumps(pfxs, indent=2))
    else:
        with open(fname) as pfxjson:
            pfxs = json.load(pfxjson)
    return pfxs

def update_prefix_file(pfxs):
    fname = './pfxs.json'
    with open(fname, mode='w') as f:
        f.write(json.dumps(pfxs, indent=2))

def get_source_addresses():
    packet = IPv6()
    packet.fields["dst"] = "ff02::1"
    interface = packet.route()[0]
    if len(netifaces.ifaddresses(interface)) > 0:
        v6addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET6]
        adds = [item['addr'].split("%")[0] for item in v6addresses]
        return adds
    else:
        return []

def isEUI64(addr):
    if not addr or "*" in addr:
        return False
    try:
        addr.split(':')
    except IndexError:
        return False

    hextets = addr.split(':')
    return hextets[-3].endswith('ff') and hextets[-2].startswith('fe')
        
def get_vendor(mac):
    if mac != "":
        maco = EUI(mac)
        try:
            return maco.oui.registration().org  
        except:                                 
            return None
    return None


class State(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.mac_to_deets = {}


class Scanner(object):

    def __init__(self, state):
        self.state = state
        self.t = AsyncSniffer(lfilter= lambda packet: IPv6 in packet, prn=lambda packet: self.parse(packet), store=0)

    def start(self):
        print("Scanner started...")
        with self.state.lock:
            self.state.mac_to_deets['Prefixes'] = get_prefixes([])
            self.state.mac_to_deets['Data'] = {}
        self.t.start()

    def stop(self):
        self.t.stop()

    def parse(self,packet):

        if ICMPv6NDOptPrefixInfo in packet:
            pf = str(packet[ICMPv6NDOptPrefixInfo].prefix)
            prefix = pf + '/'+ str(packet[ICMPv6NDOptPrefixInfo].prefixlen)
            
            latest = self.state.mac_to_deets['Prefixes']
            time_ = int(time.time()*1000)

            with self.state.lock:
                if len(latest) > 0 :
                    last_time = latest[-1]['Timestamp']
                    last_prefix = latest[-1]['Prefix']

                    if last_prefix != prefix or time_ - last_time > 3600000:
                        self.state.mac_to_deets['Prefixes'].append({"Prefix": prefix, "Timestamp": time_})
                        update_prefix_file(self.state.mac_to_deets['Prefixes'])
                else:
                    self.state.mac_to_deets['Prefixes'].append({"Prefix": prefix, "Timestamp": time_})
                    update_prefix_file(self.state.mac_to_deets['Prefixes'])
            
        
        if ICMPv6EchoReply in packet:
            mac = packet.src
            ip = packet[IPv6].src
            
            with self.state.lock:    
                if packet.src not in self.state.mac_to_deets['Data']:
                    self.state.mac_to_deets['Data'][mac] = {}

                is_eui64 = isEUI64(ip)

                if in6_isgladdr(ip):
                    self.state.mac_to_deets['Data'][mac]["Global"] = ip
                else:
                    self.state.mac_to_deets['Data'][mac]["Local"] = ip

                self.state.mac_to_deets['Data'][mac]["Vendor"] = get_vendor(mac)
                self.state.mac_to_deets['Data'][mac]["isEUI64"] = str(is_eui64)

        
        if UDP in packet and DNS in packet and packet[UDP].dport == 5353:
            
            if packet[DNS].qr == 1:
                mac = packet.src
                ip = packet[IPv6].src
                if packet.src not in self.state.mac_to_deets['Data']:
                    with self.state.lock:
                        self.state.mac_to_deets['Data'][packet.src] = {}

                        is_eui64 = isEUI64(ip)

                        if in6_isgladdr(ip):
                            self.state.mac_to_deets['Data'][mac]["Global"] = ip
                        else:
                            self.state.mac_to_deets['Data'][mac]["Local"] = ip

                        self.state.mac_to_deets['Data'][mac]["Vendor"] = get_vendor(mac)
                        self.state.mac_to_deets['Data'][mac]["isEUI64"] = str(is_eui64)

                answers = packet[DNS].fields['an']
                additional_records = packet[DNS].fields['ar']
                counter = 0
                if answers:
                    while True:
                        layer = answers.getlayer(counter)
                        if layer:
                            if layer.fields['type'] == 28:
                                with self.state.lock:
                                    self.state.mac_to_deets['Data'][mac]["device-name"] = layer.fields['rrname'].decode('utf-8')[:-1]
                        else:
                            break
                        counter+=1

                counter = 0
                if additional_records:
                    while True:
                        layer = additional_records.getlayer(counter)
                        if layer:
                            try:
                                if layer.fields['type'] == 28:
                                    with self.state.lock:
                                        self.state.mac_to_deets['Data'][mac]["device-name"] = layer.fields['rrname'].decode('utf-8')[:-1]
                            except KeyError:
                                pass
                        else:
                            break
                        counter+=1


class Requester(object):
    
    def __init__(self):
        self.lock = threading.Lock()
        self.active = False
        self.thread = threading.Thread(target=self.send_requests)
        self.thread.daemon = True

    def start(self):
        with self.lock:
            self.active = True
        self.thread.start()

    def stop(self):
        with self.lock:
            self.active = False
        self.thread.join()

    def send_requests(self):
        while True:
            # print("Sending requests..")
            self.send_echo_requests()
            self.send_unknown_param_requests()
            self.send_mdns_requests()
            time.sleep(10)

            with self.lock:
                if not self.active:
                    return

    def send_unknown_param_requests(self):
        ip_pack = IPv6()
        ip_pack.fields["version"] = 6
        ip_pack.fields["tc"] = 0
        ip_pack.fields["nh"] = 60
        ip_pack.fields["hlim"] = 255
        ip_pack.fields["dst"] = "ff02::1"

        icmp_pack = ICMPv6EchoRequest()
        icmp_pack.fields["type"] = 128
        icmp_pack.fields["code"] = 0
        icmp_pack.fields["seq"] = 1
        icmp_pack.fields["data"] = binascii.unhexlify("1234567891")

        extension = IPv6ExtHdrDestOpt(nh=58, len=0, options=[HBHOptUnknown(otype=0x80, optlen=4)])
        src_addresses = get_source_addresses()

        for src in src_addresses:
            ip_pack.fields["src"] =  src 
            pack = ip_pack / extension / icmp_pack 
            send(pack, verbose=False)
    
    def send_echo_requests(self):
        ip_pack = IPv6()
        ip_pack.fields["version"] = 6
        ip_pack.fields["tc"] = 0
        ip_pack.fields["nh"] = 58
        ip_pack.fields["hlim"] = 1
        ip_pack.fields["dst"] = "ff02::1"
        
        icmp_pack = ICMPv6EchoRequest()
        icmp_pack.fields["code"] = 0
        icmp_pack.fields["seq"] = 1
        icmp_pack.fields["type"] = 128
        icmp_pack.fields["data"] = binascii.unhexlify("1234567891")

        src_addresses = get_source_addresses()
        for src in src_addresses:
            ip_pack.fields["src"] =  src 
            pack = ip_pack / icmp_pack
            send(pack, verbose=False)
        

    def send_mdns_requests(self):
        ip_pack = IPv6()
        ip_pack.fields["version"] = 6
        ip_pack.fields["tc"] = 0
        ip_pack.fields["nh"] = 17 
        ip_pack.fields["hlim"] = 255
        ip_pack.fields["dst"] = "ff02::fb"
        
        udp_pack = UDP()
        udp_pack.fields["dport"] = 5353
        udp_pack.fields["sport"] = 5353

        queries = ['_companion-link._tcp', '_rdlink._tcp', '_device-info._tcp','_spotify-connect._tcp','_googlecast._tcp','_services._dns-sd._udp','_apple-mobdev2._tcp','_workstation_tcp', '_http_tcp', '_https_tcp', '_rss_tcp', '_domain_udp', '_ntp_udp', '_smb_tcp', '_airport_tcp', '_ftp_tcp', '_tftp_udp', '_webdav_tcp', '_webdavs_tcp', '_afpovertcp_tcp', '_nfs_tcp', '_sftp-ssh_tcp', '_apt_tcp', '_ssh_tcp', '_rfb_tcp', '_telnet_tcp', '_timbuktu_tcp', '_net-assistant_udp', '_imap_tcp', '_pop3_tcp', '_printer_tcp', '_pdl-datastream_tcp', '_ipp_tcp', '_daap_tcp', '_dacp_tcp', '_realplayfavs_tcp', '_raop_tcp', '_rtsp_tcp', '_rtp_udp', '_dpap_tcp', '_pulse-server_tcp', '_pulse-sink_tcp', '_pulse-source_tcp', '_mpd_tcp', '_vlc-http_tcp', '_presence_tcp', '_sip_udp', '_h323_tcp', '_presenc_olp', '_iax_udp', '_skype_tcp', '_see_tcp', '_lobby_tcp', '_postgresql_tcp', '_svn_tcp', '_distcc_tcp', '_MacOSXDupSuppress_tcp', '_ksysguard_tcp', '_omni-bookmark_tcp', '_acrobatSRV_tcp', '_adobe-vc_tcp', '_pgpkey-hkp_tcp', '_ldap_tcp', '_tp_tcp', '_tps_tcp', '_tp-http_tcp', '_tp-https_tcp', '_workstation._tcp', '_http._tcp', '_https._tcp', '_rss._tcp', '_domain._udp', '_ntp._udp', '_smb._tcp', '_airport._tcp', '_ftp._tcp', '_tftp._udp', '_webdav._tcp', '_webdavs._tcp', '_afpovertcp._tcp', '_nfs._tcp', '_sftp-ssh._tcp', '_apt._tcp', '_ssh._tcp', '_rfb._tcp', '_telnet._tcp', '_timbuktu._tcp', '_net-assistant._udp', '_imap._tcp', '_pop3._tcp', '_printer._tcp', '_pdl-datastream._tcp', '_ipp._tcp', '_daap._tcp', '_dacp._tcp', '_realplayfavs._tcp', '_raop._tcp', '_rtsp._tcp', '_rtp._udp', '_dpap._tcp', '_pulse-server._tcp', '_pulse-sink._tcp', '_pulse-source._tcp', '_mpd._tcp', '_vlc-http._tcp', '_presence._tcp', '_sip._udp', '_h323._tcp', '_presenc._olp', '_iax._udp', '_skype._tcp', '_see._tcp', '_lobby._tcp', '_postgresql._tcp', '_svn._tcp', '_distcc._tcp', '_MacOSXDupSuppress._tcp', '_ksysguard._tcp', '_omni-bookmark._tcp', '_acrobatSRV._tcp', '_adobe-vc._tcp', '_pgpkey-hkp._tcp', '_ldap._tcp', '_tp._tcp', '_tps._tcp', '_tp-http._tcp', '_tp-https._tcp']

        src_addresses = get_source_addresses()

        queries = [DNSQR(qtype="PTR", qname=x + ".local") for x in queries ]
        dns_seg = DNS(qd=queries)
        for src in src_addresses[:1]:
            ip_pack.fields["src"] =  src 
            pack = ip_pack / udp_pack / dns_seg
            send(pack, verbose=False)
