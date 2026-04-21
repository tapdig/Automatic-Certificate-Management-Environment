from dnslib import dns
from dnslib.server import DNSServer

DNS_PORT = 10053
HOST = "0.0.0.0"

class DnsServer:
    def __init__(self):
        self.zones = []
        self.server = DNSServer(self, port=DNS_PORT, address=HOST)

    def resolve(self, request, handler):
        reply = request.reply()
        for zone in self.zones:
            reply.add_answer(zone)
        return reply

    def update_resolver(self, domain, zone, record_type):
        if record_type == "A":
            self.zones.append(dns.RR(domain, dns.QTYPE.A, rdata=dns.A(zone), ttl=300))
            
        elif record_type == "TXT":
            self.zones.append(dns.RR(domain, dns.QTYPE.TXT, rdata=dns.TXT(zone), ttl=300))

    def start_server(self):
        self.server.start_thread()

    def stop_server(self):
        self.server.server.server_close()