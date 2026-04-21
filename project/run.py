import argparse
import requests
import base64
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa as RSA
from cryptography.hazmat.primitives import hashes
import cryptography
from cryptography import x509
from Crypto.Hash import SHA256
from flask import request
import os
import signal

from acme_client import AcmeClient
from certificate_https_server import CertificateHttpsServer
from challenge_http_server import ChallengeHttpServer
from dns_server import DnsServer
from shutdown_http_server import ShutdownHttpServer

IP = "0.0.0.0"
PORT_CERTIFICATE = 5001
PORT_CHALLENGE = 5002
PORT_SHUTDOWN = 5003
PORT_DNS = 10053

def generate_csr_and_key(domains):

    private_key = RSA.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "NetSec-ACME-Project")]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    der = csr.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER)

    return private_key, csr, der


def certificate_management(acme_client, challenge_http_server, dns_server, args):
    directory_object = acme_client.get_directory(args.dir)
    account = acme_client.create_account()
    certificate_order, order_url = acme_client.issue_certificate(args.domain)
    authorization = acme_client.authorize_identifier(certificate_order["authorizations"], args.challenge_type, challenge_http_server, dns_server)

    if not directory_object or not account or not certificate_order or not authorization:
        return False

    key, csr, der = generate_csr_and_key(args.domain)
    certificate_url = acme_client.finalize_order(order_url, certificate_order["finalize"], der)
    downloaded_certificate = acme_client.download_certificate(key, certificate_url, "privatekey.pem", "certificate.pem")

    if not certificate_url or not downloaded_certificate:
        return False

    if args.revoke:
        acme_client.revoke_certificate(
            x509.load_pem_x509_certificate(downloaded_certificate).public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.DER)
        )

    return key, downloaded_certificate

def thread_servers(server, args):
    threaded_server = Thread(target=server.start_server, args=args)
    threaded_server.start()
    return threaded_server

def main():
    parser = argparse.ArgumentParser(description="ACME Client for Certificate Management")

    parser.add_argument("challenge_type", choices=["dns01", "http01"],
                        help="ACME challenge type to perform (dns01 or http01)")

    parser.add_argument("--dir", required=True,
                        help="Directory URL of the ACME server")

    parser.add_argument("--record", required=True,
                        help="IPv4 address for A-record queries")

    parser.add_argument("--domain", required=True, nargs='+',
                        help="Domain(s) for certificate request (e.g., example.com *.example.net)")

    parser.add_argument("--revoke", action="store_true",
                        help="Revoke the certificate after obtaining it")

    args = parser.parse_args()

    # DNS Server
    dns_server = DnsServer()

    for d in args.domain:
        dns_server.update_resolver(d, args.record, "A")
    dns_server.start_server()

    # Challenge HTTP Server
    challenge_http_server = ChallengeHttpServer()
    challenge_threaded = thread_servers(challenge_http_server, args=(IP, PORT_CHALLENGE))

    # ACME Client
    acme_client = AcmeClient()

    if not acme_client or not certificate_management(acme_client, challenge_http_server, dns_server, args):
        os._exit(0)

    # Shutdown HTTP Server
    shutdown_server = ShutdownHttpServer()
    shutdown_threaded = thread_servers(shutdown_server, args=(IP, PORT_SHUTDOWN))

    # Certificate HTTPS Server
    certificate_https_server = CertificateHttpsServer()
    certificate_threaded = thread_servers(certificate_https_server, args=(IP, PORT_CERTIFICATE, "privatekey.pem", "certificate.pem"))

    # Shutting down servers
    shutdown_threaded.join()
    dns_server.stop_server()
    os._exit(0)

if __name__ == "__main__":
    main()