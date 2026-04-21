import json
import datetime
import time
import requests
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import cryptography
import base64
import Crypto

ENCODING_TYPE = "UTF-8"
CA_CERTIFICATE = "pebble.minica.pem"

class AcmeClient():
    def __init__(self):

        '''
        directory_object = {
            "newNonce": "New nonce",
            "newAccount": "New account",
            "newOrder": "New order",
            "newAuthz": "New authorization",
            "revokeCert": "Revoke certificate",
            "keyChange": "Key change"
        }
        '''

        self.directory_object = {}

        self.account_kid = None
        self.key_x = None
        self.key_y = None
        self.signature_algorithm = None

        self.client_session = requests.Session()
        self.client_session.verify = CA_CERTIFICATE

        self.client_header = {
            "User-Agent": "ACMEClient/1.0)"
        }

        self.jose_header = {
            "User-Agent": "ACMEClient/1.0)",
            "Content-Type": "application/jose+json"
        }

    def custom_b64encode(self, data):
        if type(data) == str:
            data = data.encode(ENCODING_TYPE)

        encoded_data = base64.urlsafe_b64encode(data).decode(ENCODING_TYPE).rstrip("=")

        return encoded_data
    
    def generate_response(self, url, body):
        response = self.client_session.post(url, json=body, headers=self.jose_header)
        return response
    
    def hash_encoded(self, data, encoding_type):
        encoded = str.encode(data, encoding=encoding_type)
        hashed_data = Crypto.Hash.SHA256.new(encoded)
        return hashed_data

    def get_directory(self, directory):
        response = self.client_session.get(directory, headers=self.client_header)

        if response.status_code == 200:
            self.directory_object = response.json()
            print(f"Directory Object: {self.directory_object}")

            return self.directory_object

    def get_nonce(self):
        fresh_nonce = self.directory_object["newNonce"]

        if fresh_nonce:
            response = self.client_session.get(fresh_nonce, headers=self.client_header)

            if response.status_code in [200, 204]:
                return response.headers["Replay-Nonce"]
        return False

    def create_account(self):
        keypair = ECC.generate(curve="p256")

        self.key_x, self.key_y = keypair.pointQ.x, keypair.pointQ.y
        self.signature_algorithm = DSS.new(keypair, "fips-186-3")

        # JWS Protected Header
        protected_header = {
            "alg": "ES256",
            "nonce": self.get_nonce(),
            "url": self.directory_object["newAccount"],
            "jwk": {
                "crv": "P-256",
                "kty": "EC",
                "x": self.custom_b64encode(self.key_x.to_bytes()),
                "y": self.custom_b64encode(self.key_y.to_bytes()),
            }
        }

        encoded_header = self.custom_b64encode(json.dumps(protected_header))
        encoded_payload = self.custom_b64encode(json.dumps({
            "termsOfServiceAgreed": True,
            "contact": ["mailto:admin@example.com"]
        }))

        # Hash the concatenated header and payload
        hash_value = self.hash_encoded(f"{encoded_header}.{encoded_payload}", "ascii")

        # Generate a signature and encode it
        signature = self.custom_b64encode(self.signature_algorithm.sign(hash_value))

        request_body = {
            "protected": encoded_header,
            "payload": encoded_payload,
            "signature": signature,
        }

        response = self.generate_response(self.directory_object["newAccount"], request_body)
        
        # Create account | POST newAccount | 201 -> account (Location header)
        if response.status_code == 201:
            self.account_kid = response.headers["Location"]
            return response.json()

    def create_payload(self, url, payload):

        protected = {
            "alg": "ES256",
            "kid": self.account_kid,
            "nonce": self.get_nonce(),
            "url": url,
        }

        encoded_protected = self.custom_b64encode(json.dumps(protected))

        if payload == "":
            encoded_payload = ""
            hash_value = self.hash_encoded(f"{encoded_protected}.", "ascii")
        elif payload != "":
            encoded_payload = self.custom_b64encode(json.dumps(payload))
            hash_value = self.hash_encoded(f"{encoded_protected}.{encoded_payload}", "ascii")

        signature = self.custom_b64encode(self.signature_algorithm.sign(hash_value))

        data = {
            "protected": encoded_protected,
            "payload": encoded_payload,
            "signature": signature,
        }

        return data

    def issue_certificate(self, domains):

        payload = {
            "identifiers": [{"type": "dns", "value": domain} for domain in domains]
        }

        body = self.create_payload(self.directory_object["newOrder"], payload)

        response = self.generate_response(self.directory_object["newOrder"], body)

        if response.status_code == 201:
            return response.json(), response.headers["Location"]

    def authorize_identifier(self, auth_urls, challenge_type, challenge_server, dns_server):

        key = {
            "crv": "P-256",
            "kty": "EC",
            "x": self.custom_b64encode(self.key_x.to_bytes()),
            "y": self.custom_b64encode(self.key_y.to_bytes()),
        }

        hash_value = self.custom_b64encode(self.hash_encoded(json.dumps(key, separators=(',', ':')), "utf-8").digest())

        valid_urls = []

        for url in auth_urls:
            request_body = self.create_payload(url, "")
            response = self.generate_response(url, request_body)

            if response.status_code == 200:
                response_object = response.json()
                if response_object["challenges"]:
                    for challenge in response_object["challenges"]:
                        key_authorization = f"{challenge['token']}.{hash_value}"

                        if challenge_type == "dns01" and challenge["type"] == "dns-01":
                            key_authorization = self.custom_b64encode(self.hash_encoded(key_authorization, "ascii").digest())
                            dns_server.update_resolver(
                                f"_acme-challenge.{response_object['identifier']['value']}",
                                key_authorization, "TXT"
                            )
                            valid_urls.append(challenge["url"])

                        elif challenge_type == "http01" and challenge["type"] == "http-01":
                            challenge_server.register_challenge(challenge["token"], key_authorization)
                            valid_urls.append(challenge["url"])
                else:
                    return False
            else:
                return False
        if not valid_urls:
            return False
        for url in valid_urls:
            request_body = self.create_payload(url, {})
            response = self.generate_response(url, request_body)
            if response.status_code == 200:
                pass
            else:
                return False
        return True

    def poll_status(self, successful_states, failed_states, url):
        while True:
            request_body = self.create_payload(url, "")
            response = self.generate_response(url, request_body)

            if response.status_code == 200 and response.json()["status"] in successful_states:
                return response.json()
            elif response.status_code == 200 and response.json()["status"] in failed_states:
                return False
                
    def download_certificate(self, key, certificate_url, key_path, certificate_path):
        request_body = self.create_payload(certificate_url, "")
        response = self.generate_response(certificate_url, request_body)

        if response.status_code == 200:
            downloaded_certificate = response.content

            # saving certificate and key files
            with open(certificate_path, "wb") as certificate_file:
                certificate_file.write(downloaded_certificate)

            with open(key_path, "wb") as key_file:
                key_file.write(
                    key.private_bytes(
                        encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
                        format=cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()
                    )
                )

            return downloaded_certificate

    def finalize_order(self, order_url, finalize_url, der):
        if not self.poll_status(["ready", "processing", "valid"], ["invalid"], order_url):
            return False

        body = self.create_payload(finalize_url, {"csr": self.custom_b64encode(der)})

        response = self.generate_response(finalize_url, body)
        response_object = self.poll_status(["valid"], ["ready", "invalid", "pending"], order_url)
            
        return response_object["certificate"] if response.status_code == 200 else False

    def revoke_certificate(self, certificate):
        request_body = self.create_payload(
            self.directory_object["revokeCert"],
            {"certificate": self.custom_b64encode(certificate)}
        )
        
        response = self.generate_response(self.directory_object["revokeCert"], request_body)
        
        return response.content if response.status_code == 200 else None