
# #PART 1- LOCATING DOMAIN CAs
#
# DNS_SERVER = "8.8.8.8"
# UDP_PORT = 53#
#
# domaininput = input("Enter domain address: ")
#
# # Create DNS query
# dns_query = DNS(rd=1, qd=DNSQR(qname=domaininput, qtype='CAA'))
#
# # Send DNS query and receive response
# response = sr1(IP(dst=DNS_SERVER)/UDP(dport=UDP_PORT)/dns_query, verbose=False)
#
# # Check if response is received
# if response and response.haslayer(DNS):
#     dns_response = response[DNS]
#     if dns_response.an:
#         print("CAA Records Found:")
#         for answer in dns_response.an:
#             if answer.type == 257:  # CAA record type
#                 print(answer.rdata)
#     else:
#         print("No CAA Records Found")
# else:
#     print("No response received from DNS server.")


#-------------------------PART TWO- DNS ENUMERATION----------------------------

# def load_wordlist(filename):
#     with open(filename, 'r') as file:
#         return [line.strip() for line in file]
#
# def load_dnsmap(filename):
#     with open(filename, 'r') as file:
#         return file.read()
#
# import socket
# import sys
#
# wordlist = load_wordlist('wordlist_TLAs.txt')
# dnsmap = load_dnsmap('dnsmap.h')
#
# domain = input("Enter domain name: ")  # www.domain.com
# #Iterate through prefixes in the wordlist
# for prefix in wordlist:
#     try:
#         if not prefix or prefix.startswith('#'):
#             continue  # Skip empty lines or comments
#         # Concatenate prefix with the domain
#         subdomain = f"{prefix}.{domain}"
#         ip = socket.gethostbyname(subdomain)
#         print("Subdomain found: " + subdomain)
#         print("IP address: " + ip)
#
#     except socket.gaierror:
#         #print('Invalid Domain.\n')
#         pass
#         #sys.exit()

#----------------------------PART THREE- WHOIS---------------------------------


# import socket
# from scapy.all import sr1, IP, TCP, Raw
#
# WHOIS_PORT = 43
#
# def whois_lookup(domain, whois_server):
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.connect((whois_server, WHOIS_PORT))
#             s.send(f"{domain}\r\n".encode())
#
#             response = b""
#             while True:
#                 data = s.recv(4096)
#                 if not data:
#                     break
#                 response += data
#
#                 # Record server's reply using Scapy
#                 response_packet = IP(dst=whois_server) / TCP(dport=WHOIS_PORT, sport=s.getsockname()[1], flags="A") / Raw(load=response)
#         return response_packet
#     except Exception as e:
#         print(f"Error: {e}")
#         return None
#
#
# def find_whois_server(domain):
#     try:
#         # Query whois.iana.org to find the WHOIS server for the domain
#         response = whois_lookup(domain, "whois.iana.org")
#         if response:
#             response_text = str(response[Raw].load.decode())
#             for line in response_text.split('\n'):
#                 if line.lower().startswith("whois"):
#                     whois_server = line.split(":")[1].strip()
#                     return whois_server
#         else:
#             return None
#     except Exception as e:
#         print(f"Error finding WHOIS server for {domain}: {e}")
#         return None
#
#
# if __name__ == "__main__":
#     domain = input("Enter domain: ")
#     whois_server = find_whois_server(domain)
#     if whois_server:
#         print(f"WHOIS server for {domain}: {whois_server}")
#
#         # Perform WHOIS lookup using the obtained WHOIS server
#         response_packet = whois_lookup(domain, whois_server)
#         decoded_response = response_packet[Raw].load.decode('unicode_escape')
#         print(decoded_response)
#     else:
#         print("Failed to find WHOIS server for the domain.")


import sys
import socket
from scapy.all import sr1, IP, UDP, DNS, DNSQR, TCP, Raw

WHOIS_PORT = 43

def whois_lookup(domain, whois_server):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((whois_server, WHOIS_PORT))
            s.send(f"{domain}\r\n".encode())

            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data

            # Record server's reply using Scapy
            response_packet = IP(dst=whois_server) / TCP(dport=WHOIS_PORT, sport=s.getsockname()[1], flags="A") / Raw(load=response)
        return response_packet
    except Exception as e:
        print(f"Error: {e}")
        return None


def find_whois_server(domain):
    try:
        # Query whois.iana.org to find the WHOIS server for the domain
        response = whois_lookup(domain, "whois.iana.org")
        if response:
            response_text = str(response[Raw].load.decode())
            for line in response_text.split('\n'):
                if line.lower().startswith("whois"):
                    whois_server = line.split(":")[1].strip()
                    return whois_server
        else:
            return None
    except Exception as e:
        print(f"Error finding WHOIS server for {domain}: {e}")
        return None


def dns_lookup(domain, dns_server="8.8.8.8", udp_port=53):
    try:
        # Create DNS query
        dns_query = DNS(rd=1, qd=DNSQR(qname=domain, qtype='CAA'))

        # Send DNS query and receive response
        response = sr1(IP(dst=dns_server) / UDP(dport=udp_port) / dns_query, verbose=False)

        # Check if response is received
        if response and response.haslayer(DNS):
            dns_response = response[DNS]
            if dns_response.an:
                print("CAA Records Found:")
                for answer in dns_response.an:
                    if answer.type == 257:  # CAA record type
                        print(answer.rdata)
            else:
                print("No CAA Records Found")
        else:
            print("No response received from DNS server.")
    except Exception as e:
        print(f"Error: {e}")


def subdomain_enum(domain, wordlist_filename='wordlist_TLAs.txt'):
    try:
        with open(wordlist_filename, 'r') as file:
            wordlist = [line.strip() for line in file]

        for prefix in wordlist:
            try:
                if not prefix or prefix.startswith('#'):
                    continue  # Skip empty lines or comments
                # Concatenate prefix with the domain
                subdomain = f"{prefix}.{domain}"
                ip = socket.gethostbyname(subdomain)
                print("Subdomain found: " + subdomain)
                print("IP address: " + ip)

            except socket.gaierror:
                pass
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python dnstoolkit.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    whois_server = find_whois_server(domain)
    if whois_server:
        print(f"WHOIS server for {domain}: {whois_server}")
        response_packet = whois_lookup(domain, whois_server)
        decoded_response = response_packet[Raw].load.decode('unicode_escape')
        print(decoded_response)
    else:
        print("Failed to find WHOIS server for the domain.")

    dns_lookup(domain)

    subdomain_enum(domain)
