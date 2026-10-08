from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6
from scapy.layers.tls.all import TLSClientHello, ServerName

class ApplicationIdentifier:

    def process_tls_packet(self, packet):
        if TLSClientHello not in packet:
            return

        print("TLS CLIENT HELLO FOUND")

        try:
            current = packet[TLSClientHello]
            print(current.show(dump=True))

            if ServerName in current:
                print("SNI FOUND")
                server_name = current[ServerName].servername
                print("SNI:", server_name)

        except Exception as e:
            print("TLS ERROR:", e)

    def __init__(self):
        self.ip_to_domain = {}

        self.application_map = {
            "youtube.com": "YouTube",
            "googlevideo.com": "YouTube",
            "ytimg.com": "YouTube",

            "meet.google.com": "Google Meet",
            "gmail.com": "Gmail",
            "googlemail.com": "Gmail",
            "mail.google.com": "Gmail",

            "play.google.com": "Google Play",
            "google.com": "Google",
            "googleapis.com": "Google",
            "gstatic.com": "Google",

            "chatgpt.com": "ChatGPT",
            "openai.com": "ChatGPT",

            "github.com": "GitHub",
            "githubusercontent.com": "GitHub",

            "instagram.com": "Instagram",
            "cdninstagram.com": "Instagram",

            "facebook.com": "Facebook",
            "fbcdn.net": "Facebook",

            "whatsapp.com": "WhatsApp",
            "whatsapp.net": "WhatsApp",

            "netflix.com": "Netflix",
            "nflxvideo.net": "Netflix"
        }

    def process_dns_packet(self, packet):

        if DNS not in packet:
            return

        if packet[DNS].qr == 1 and packet[DNS].ancount > 0:

            for i in range(packet[DNS].ancount):

                answer = packet[DNS].an[i]

                if DNSRR in answer:

                    domain = answer.rrname.decode("utf-8").rstrip(".")

                    if answer.type == 1:
                        self.ip_to_domain[answer.rdata] = domain

                    elif answer.type == 28:
                        self.ip_to_domain[answer.rdata] = domain

    def get_domain(self, ip):

        return self.ip_to_domain.get(ip)

    def get_application(self, domain, ip=None):

        # Localhost
        if ip in ["127.0.0.1", "::1", "localhost"]:
            return "Localhost"

        # No domain
        if not domain:
            return "Unknown"

        domain = domain.lower().rstrip(".")

        # Ignore local network service discovery
        if domain.endswith(".local"):
            return "Local Network"

        for known_domain, application in self.application_map.items():
            if domain == known_domain or domain.endswith("." + known_domain):
                return application

        return domain