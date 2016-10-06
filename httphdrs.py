#!/usr/bin/env python2

# httphdrs.py
# HTTP headers monitoring
# @author: Martin Borek (xborek08)


import sys
import argparse
#from lxml import etree as ET
import xml.etree.ElementTree as ET
import signal

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
from scapy.all import *


global_headers = ()

# Methods in HTTP packets (see RFC 7231, section 4.1 - Request Methods Overview)
global_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS",
        "TRACE"] 


class Params:
    '''Class for handling and parsing given arguments.'''

    def __init__(self):
        self.input_file = None
        self.output = None
        self.interface = None # "None" ~ pcap file in self.input_file is set
        self.headers = ('User-Agent', 'Accept', 'Accept-Encoding',
                'Accept-Language') # HTTP headers to be monitored
        self.ports = [80] # Ports to be searched

    def _set_output_file(self, filename):
        self.output_file = filename

    def _set_input_file(self, filename):
        self.input_file = filename

    def _set_interface(self, interface):
        self.interface = interface

    def _set_ports(self, ports):
        try:
            # Make a list of integers and remove emtpy strings
            self.ports = [int(x) for x in ports.split(',') if x]
        except:
            raise ArgError("Invalid port entered.")
       
    def _set_headers(self, headers):
        # Make a list and remove empty strings
        self.headers = tuple([x for x in headers.split(',') if x])
        if not self.headers:
            raise ArgError("No header entered.")

    def get_args(self):
        '''Parses given arguments. Uses methods defined above.'''

        #try:
        arg_parser = argparse.ArgumentParser(
                description="HTTP headers monitoring")
        exclusive = arg_parser.add_mutually_exclusive_group(required=True)
        exclusive.add_argument('-i', help="interface to be monitored")
        exclusive.add_argument('-f', help="pcap file to be searched")
        arg_parser.add_argument('-o', required=True, help="output file")
        arg_parser.add_argument('-H', help="HTTP headers to be searched for") 
        arg_parser.add_argument('-p',
                help="TCP ports of HTTP servers to be searched")
        args = arg_parser.parse_args()
        #except:
        #    raise ArgError("Wrong argument(s) entered.")
       
        if args.i is not None:
            self._set_interface(args.i)
        else:
            self._set_input_file(args.f)

        self._set_output_file(args.o)

        if args.H is not None:
            self._set_headers(args.H) 

        if args.p is not None:
            self._set_ports(args.p)


class ArgError(Exception):
    '''Exception as a result of wrong arguments entered.'''

    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class SniffError(Exception):
    '''Exception as a result of wrong Scapy.sniff arguments.'''

    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class FileError(Exception):
    '''Exception as a result of wrong Scapy.sniff arguments.'''

    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class Header():
    '''Header to be stored. Contains a name and a value.'''

    def __init__(self, field_name, field_value):
        self.name = field_name
        self.value = field_value


class Connection():
    '''Connection to be stored. Contains a header and a port number.'''
    
    def __init__(self, port, headers):
        self.port = port
        self.headers = headers


def append_connection(dict_ips, ip, port, connection):
    '''Appends new connection to a given dictionary (IPs).

       dict_ips: Dictionary ip->connection
       ip: Source IP
       port: Source port number
       connection: Raw data from the connection
       '''

#    if IP not in x:
#        print(x[1].src + "\r\n")
#        return

    headers = []

    # Check all headers in the connection
    for header in connection.split('\r\n'):

        parts = header.partition(':')
        field_name = parts[0].strip()
        field_value = parts[2].strip()
        
        # Does it match the header type that should be monitored? Append.
        if field_name.lower() in global_headers:
            headers.append(Header(field_name, field_value))

    # List of headers created, create Connection and
    # append to dictionary of IPs
    if ip in dict_ips:
        dict_ips[ip].append(Connection(port, headers))
    else:
        dict_ips[ip] = [Connection(port, headers)]

def create_xml(data, output_file):
    '''Create XML tree and save to file.''' 
    
    xml_root = ET.Element("httphdrs") 
    xml_tree = ET.ElementTree(xml_root)        

    for ip, connections in data.items():
        ip_node = ET.SubElement(xml_root, "ip", {"addr": ip})
        for connection in connections:
            connection_node = ET.SubElement(ip_node, "connection",
                    {"port": str(connection.port)})
            for header in connection.headers:
                header_node = ET.SubElement(connection_node, "header",
                        {"name": header.name, "value": header.value})
        
    #xml_tree.write(output_file, encoding='utf-8', xml_declaration=True,
    #        pretty_print=True)

    xml_tree.write(output_file, encoding='utf-8', xml_declaration=True)

def main():
    '''MAIN PROGRAM'''

    err_code = 0

    ips_dict = dict();

    try:
        params = Params()
        params.get_args()

        global global_headers # header types to be monitored
        # lower() used because headers are case insensitive (RFC 7230, section 3.2)
        global_headers = tuple([x.lower() for x in params.headers])

        # Monitor communication at given interface till ending signal received
        if params.input_file is None:

            def interupt_handler(signal, frame):
                '''Received signal to end monitoring and save data.'''

                create_xml(ips_dict, params.output_file)
                exit(0)

            signal.signal(signal.SIGINT, interupt_handler)
            signal.signal(signal.SIGTERM, interupt_handler)
            signal.signal(signal.SIGQUIT, interupt_handler)

        # Filter used in Scapy.sniff.
        # Filters only HTTP packets with given port number.
        # HTTP packets filter based on searching for HTTP
        # Methods (RFC 7231, section 4.1 - Request Methods Overview).
        my_filter = lambda (x):( TCP in x and Raw in x and
            (x[TCP].dport in params.ports) and
            x[TCP][Raw].load.partition(' ')[0] in global_methods
        )
        
        # Function to be called in Scapy.sniff whenever a packet
        # matches criteria. Data are appended to dictionary of IPs.
        my_prn = lambda (x):(append_connection(ips_dict, x[1].src, x[TCP].sport,
                x[TCP][Raw].load.partition('\r\n\r\n')[0]))

        if params.input_file is not None:
            # Sniff file.
            try:
                sniff(offline=params.input_file, prn=my_prn, lfilter=my_filter)
            except IOError:
                raise FileError("This file could not be opened")

            create_xml(ips_dict, params.output_file)

        else:
            # Sniff interface  
            try:
                sniff(iface=params.interface, prn=my_prn, lfilter=my_filter)
            except socket.error as e:
                #print(sys.exc_info()[0])
                #exit(0)
                if e.errno == 1:
                    # "sudo issue"
                    raise SniffError("You don't have permission to monitor this interface.")
                else:
                    raise SniffError("Interface \"" + params.interface +"\" cannot be monitored.")


    #version for Python4: except ArgError as e:
    except ArgError:
        t, e = sys.exc_info()[:2] # handles python2 as well as python3
        sys.stderr.write("Arguments error: " + e.value + "\n")
        err_code = 1
    except FileError:
        t, e = sys.exc_info()[:2] # handles python2 as well as python3
        sys.stderr.write("File error: " + e.value + "\n")
        err_code = 1
    except SniffError:
        t, e = sys.exc_info()[:2] # handles python2 as well as python3
        sys.stderr.write("Sniffing error: " + e.value + "\n")
        err_code = 1
    except Exception:
        t, e = sys.exc_info()[:2]
        sys.stderr.write(traceback.format_exc())
        #sys.stderr.write("Error: Monitoring not successful.\n")
        err_code = 2
    finally:
        exit(err_code)

main()
