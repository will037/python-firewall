import time
import socket
import dns.message
import dns.query
import dns.rdatatype
import select

def load_blacklist(blacklist_file):
    blacklist = {}
    with open(blacklist_file, 'r') as f:
        for line in f:
            domain, ip = line.strip().split('::')
            blacklist[domain] = ip
    print(f"Loaded blacklist: {blacklist}")
    return blacklist

def send_dns_query(domain, dns_server, timeout=5):
    qname = dns.name.from_text(domain)
    query_a = dns.message.make_query(qname, dns.rdatatype.A)
    query_aaaa = dns.message.make_query(qname, dns.rdatatype.AAAA)
    response_a = dns.query.udp(query_a, dns_server, timeout=timeout)
    response_aaaa = dns.query.udp(query_aaaa, dns_server, timeout=timeout)
    return response_a, response_aaaa

def send_dns_query_with_retry(domain, dns_servers, retries=3, timeout=5):
    for attempt in range(retries):
        for dns_server in dns_servers:
            try:
                return send_dns_query(domain, dns_server, timeout)
            except (ConnectionResetError, dns.exception.Timeout) as e:
                print(f"Attempt {attempt + 1} with DNS server {dns_server} failed with error: {e}, retrying...")
                time.sleep(1)
    raise ConnectionResetError("All retry attempts with all DNS servers failed")

def get_blacklisted_ip(domain, blacklist):
    domain_parts = domain.split('.')
    for i in range(len(domain_parts)):
        subdomain = '.'.join(domain_parts[i:])
        if subdomain in blacklist:
            print(f"Domain {domain} or its parent domain {subdomain} is blacklisted")
            return blacklist[subdomain]
    return None

def create_block_response(query, blacklisted_ip):
    response = dns.message.make_response(query)
    # Instead of returning a mapped IP, return a NXDOMAIN or redirect to a block page.
    response.set_rcode(dns.rcode.NXDOMAIN)  # Or use a redirect (see below)
    return response

def start_dns_server(listening_ip, listening_port, dns_servers, blacklist_file):
    while True:
        try:
            blacklist = load_blacklist(blacklist_file)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((listening_ip, listening_port))
            sock.setblocking(0)

            print(f"DNS server listening on {listening_ip}:{listening_port}")

            while True:
                ready = select.select([sock],,, 5)
                if ready:
                    data, addr = sock.recvfrom(512)
                    print(f"Received query from {addr}")

                    query = dns.message.from_wire(data)
                    domain = str(query.question.name)
                    print(f"Parsed domain: {domain}")

                    blacklisted_ip = get_blacklisted_ip(domain, blacklist)
                    if blacklisted_ip:
                        print(f"Domain {domain} is blacklisted.")
                        response = create_block_response(query, blacklisted_ip)
                        sock.sendto(response.to_wire(), addr)
                        continue

                    response_a, response_aaaa = send_dns_query_with_retry(domain, dns_servers)

                    combined_response = dns.message.make_response(query)
                    combined_response.answer.extend(response_a.answer)
                    combined_response.answer.extend(response_aaaa.answer)

                    sock.sendto(combined_response.to_wire(), addr)
                    print(f"Sent response to {addr}")
                else:
                    print("No data received within the timeout period. Restarting the DNS server...")
                    break

        except Exception as e:
            print(f"Unexpected error: {e}. Restarting the DNS server...")

        finally:
            sock.close()
            print("All sessions reset. Restarting the server...")


listening_ip = '192.168.11.22'
listening_port = 53
dns_servers = ['8.8.8.8', '8.8.4.4']
blacklist_file = 'C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python312-32\\blacklist.txt'

start_dns_server(listening_ip, listening_port, dns_servers, blacklist_file)


'''


Key Changes and Explanations:

create_block_response Function:  This new function handles creating the DNS response when a domain is blacklisted.  Instead of trying to fake an IP address, the most reliable way to block a site at the DNS level is to return NXDOMAIN (Non-Existent Domain).  This tells the client the domain doesn't exist.

Redirect to Block Page (Advanced):  If you want to redirect to a block page, you would need to set up a web server on your network (e.g., on the same machine running the DNS server).  Then, in create_block_response, you would craft a response that includes a CNAME record pointing to your block page's domain.  However, this requires more setup.  The NXDOMAIN approach is simpler and usually sufficient for blocking.

Removed IP Mapping:  The code no longer attempts to map blacklisted domains to specific IPs.  Returning NXDOMAIN is the standard practice for blocking.

Blacklist File Format: The code assumes your blacklist file is still in the domain::ip format.  While the ip part is no longer used for blocking, you can keep it in the file for your own record-keeping if you wish.  Just make sure the code splits the line correctly.

Error Handling:  The try...except...finally block is essential for catching potential errors and ensuring the socket is always closed properly.

How to use:

Blacklist File: Create your blacklist.txt file. For simple blocking, you can use the domain::ip format. The IP will be ignored, but you can put a placeholder there. Example:

example.com::127.0.0.1
baddomain.net::127.0.0.1
anotherbadsite.org::127.0.0.1
Run the Script: Save the code as a Python file (e.g., dns_blocker.py) and run it: python dns_blocker.py

Configure Client DNS: On the computer you want to protect, change the DNS settings to point to the IP address of the machine running your DNS blocker script (192.168.11.22 in this example).

Now, when a user tries to access a blacklisted domain, their DNS request will be intercepted, and your server will return NXDOMAIN, preventing them from reaching the site.

Important Considerations:

Root Privileges (Port 53): Running a DNS server on port 53 usually requires root or administrator privileges.
Firewall: Make sure your firewall allows UDP traffic on port 53.
Testing: Use nslookup or dig from a client machine to test if the blocking is working correctly. For example, nslookup example.com should return "NXDOMAIN" if example.com is in your blacklist.
Caching: Clients and other DNS servers might cache the NXDOMAIN response. You might need to clear the DNS cache on your client machines or wait for the TTL (Time To Live) to expire.
Redirect (Advanced): If you implement the redirect, make absolutely certain your web server for the block page is configured correctly to prevent open redirects (where blocked domains could redirect to arbitrary sites).

'''
