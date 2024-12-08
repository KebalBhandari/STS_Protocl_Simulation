import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from Crypto.Cipher import AES
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding as asym_padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature  # Added import


class CertificateAuthority:

    def __init__(self):
        self.private_key_path = Path("./certificates/ca_private_key.pem")
        self.certificate_path = Path("./certificates/ca_certificate.pem")
        self.certificate_path.parent.mkdir(parents=True, exist_ok=True)
        if self.private_key_path.exists() and self.certificate_path.exists():
            self.load_ca_key_and_certificate()
        else:
            self.generate_ca_key_and_certificate()
            self.save_ca_key_and_certificate()

    def generate_ca_key_and_certificate(self):
        self.ca_private_key = rsa.generate_private_key(public_exponent=65537,
                                                       key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'Simulated CA'),
        ])
        self.ca_certificate = x509.CertificateBuilder().subject_name(
            subject).issuer_name(issuer).public_key(
                self.ca_private_key.public_key()).serial_number(
                    x509.random_serial_number()).not_valid_before(
                        datetime.now(timezone.utc)).not_valid_after(
                            datetime.now(timezone.utc) +
                            timedelta(days=365)).sign(self.ca_private_key,
                                                      hashes.SHA256())

    def save_ca_key_and_certificate(self):
        with open(self.private_key_path, "wb") as f:
            f.write(
                self.ca_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()))
        with open(self.certificate_path, "wb") as f:
            f.write(
                self.ca_certificate.public_bytes(serialization.Encoding.PEM))

    def load_ca_key_and_certificate(self):
        with open(self.private_key_path, "rb") as f:
            self.ca_private_key = serialization.load_pem_private_key(
                f.read(), password=None)
        with open(self.certificate_path, "rb") as f:
            self.ca_certificate = x509.load_pem_x509_certificate(f.read())

    def sign_certificate(self, csr):
        certificate = x509.CertificateBuilder().subject_name(
            csr.subject).issuer_name(self.ca_certificate.subject).public_key(
                csr.public_key()).serial_number(
                    x509.random_serial_number()).not_valid_before(
                        datetime.now(timezone.utc)).not_valid_after(
                            datetime.now(timezone.utc) +
                            timedelta(days=365)).sign(self.ca_private_key,
                                                      hashes.SHA256())
        return certificate


class Participant:

    def __init__(self, name, ca):
        self.name = name
        self.ca = ca
        self.certificate_path = Path(
            f"./certificates/{self.name}_certificate.pem")
        self.private_key_path = Path(
            f"./certificates/{self.name}_private_key.pem")
        self.dh_private_key_path = Path(
            f"./certificates/{self.name}_dh_private_key.pem")

        self.certificate_path.parent.mkdir(parents=True, exist_ok=True)

        if (self.certificate_path.exists() and self.private_key_path.exists()
                and self.dh_private_key_path.exists()):
            self.load_certificate_and_keys()
        else:
            self.generate_dh_parameters()
            self.generate_dh_key_pair()
            self.generate_signing_key_pair()
            self.create_certificate()
            self.save_certificate_and_keys()

        self.packet_number = 0
        self.last_received_packet_number = 0
        self.source_mac = bytes.fromhex('66778899aabb')
        self.priority = b'\x00'
        self.dh_parameters_set = False
        self.initial_params_sent = False

    def generate_dh_parameters(self):
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.dh_p = self.dh_parameters.parameter_numbers().p
        self.dh_g = self.dh_parameters.parameter_numbers().g

    def generate_dh_key_pair(self):
        if self.dh_parameters:
            self.dh_private_key = self.dh_parameters.generate_private_key()
            self.dh_public_key = self.dh_private_key.public_key()
        else:
            self.dh_private_key = None
            self.dh_public_key = None

    def generate_signing_key_pair(self):
        self.signing_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048)
        self.signing_public_key = self.signing_private_key.public_key()

    def create_certificate(self):
        common_name = f"{self.name.lower()}.example.com"
        san = x509.SubjectAlternativeName([
            x509.DNSName(common_name),
            x509.DNSName(f"{self.name.lower()}.internal.example.com"),
            x509.DNSName(f"{self.name.lower()}.local.example.com")
        ])

        dh_params_value = f"p={self.dh_p},g={self.dh_g}".encode()
        dh_extension = x509.UnrecognizedExtension(
            oid=x509.ObjectIdentifier("1.2.3.4.5.6.7.8.1"),
            value=dh_params_value)

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])).add_extension(san,
                              critical=False).add_extension(dh_extension,
                                                            critical=False)

        csr = csr_builder.sign(self.signing_private_key, hashes.SHA256())
        self.certificate = self.ca.sign_certificate(csr)

    def save_certificate_and_keys(self):
        with open(self.certificate_path, "wb") as f:
            f.write(self.certificate.public_bytes(serialization.Encoding.PEM))

        with open(self.private_key_path, "wb") as f:
            f.write(
                self.signing_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()))

        with open(self.dh_private_key_path, "wb") as f:
            f.write(
                self.dh_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()))

    def load_certificate_and_keys(self):
        with open(self.certificate_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())

        with open(self.private_key_path, "rb") as f:
            self.signing_private_key = serialization.load_pem_private_key(
                f.read(), password=None)
        self.signing_public_key = self.signing_private_key.public_key()

        with open(self.dh_private_key_path, "rb") as f:
            self.dh_private_key = serialization.load_pem_private_key(
                f.read(), password=None)
        self.dh_public_key = self.dh_private_key.public_key()

        dh_parameters_numbers = self.dh_private_key.private_numbers(
        ).public_numbers.parameter_numbers
        self.dh_p = dh_parameters_numbers.p
        self.dh_g = dh_parameters_numbers.g
        self.dh_parameters = dh_parameters_numbers.parameters()

    def send_message(self, data, recipient_name, message_type="protocol"):
        if message_type == "protocol":
            dh_public_bytes = data.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo)

            message = {
                'dh_public_bytes':
                dh_public_bytes,
                'certificate_bytes':
                self.certificate.public_bytes(serialization.Encoding.PEM),
            }

            if self.name == "Alice" and not self.initial_params_sent:
                message['alpha'] = self.dh_g
                message['p'] = self.dh_p
                self.initial_params_sent = True

            if hasattr(self, 'peer_dh_public_key'):
                self.shared_secret = self.dh_private_key.exchange(
                    self.peer_dh_public_key)
                self.derive_session_key()
                data_to_sign = dh_public_bytes + \
                    self.peer_dh_public_key.public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                signature = self.signing_private_key.sign(
                    data_to_sign, asym_padding.PKCS1v15(), hashes.SHA256())
                encrypted_signature, packet_number = self.encrypt_data(
                    signature)
                message['encrypted_signature'] = encrypted_signature
                message['packet_number'] = packet_number

        else:
            # Encrypted message handling
            encrypted_data, packet_number = self.encrypt_data(data.encode())
            message = {
                'encrypted_data': encrypted_data,
                'packet_number': packet_number
            }

        print(
            f"{self.name} sends a {message_type} message to {recipient_name}.")
        return message

    def receive_message(self, message, sender_name, message_type="protocol"):
        if message_type == "protocol":
            if 'alpha' in message and 'p' in message and not self.dh_parameters_set:
                self.peer_dh_g = message['alpha']
                self.peer_dh_p = message['p']
                self.dh_parameters = dh.DHParameterNumbers(
                    self.peer_dh_p, self.peer_dh_g).parameters()
                self.generate_dh_key_pair()
                self.dh_parameters_set = True
                print(
                    f"{self.name} sets DH parameters from {sender_name}'s message."
                )

            self.peer_dh_public_key = serialization.load_pem_public_key(
                message['dh_public_bytes'])
            self.peer_certificate = x509.load_pem_x509_certificate(
                message['certificate_bytes'])
            self.verify_certificate(self.peer_certificate)

            if 'encrypted_signature' in message:
                self.encrypted_signature = message['encrypted_signature']
                received_packet_number = message.get('packet_number')
                self.shared_secret = self.dh_private_key.exchange(
                    self.peer_dh_public_key)
                self.derive_session_key()
                signature = self.decrypt_data(self.encrypted_signature,
                                              received_packet_number)
                data_to_verify = message['dh_public_bytes'] + \
                    self.dh_public_key.public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                self.verify_signature(signature, data_to_verify)
        else:
            encrypted_data = message['encrypted_data']
            received_packet_number = message.get('packet_number')
            print(
                f"{self.name} received encrypted message from {sender_name}: {bytes(encrypted_data).hex()}"
            )
            decrypted_data = self.decrypt_data(encrypted_data,
                                               received_packet_number)
            print(
                f"{self.name} decrypted message from {sender_name}: {decrypted_data.decode()}"
            )

    def encrypt_data(self, data):
        self.packet_number += 1
        nonce = self.construct_nonce(self.packet_number)
        cipher = AES.new(self.session_key, AES.MODE_CTR, nonce=nonce)
        encrypted_data = cipher.encrypt(data)
        return encrypted_data, self.packet_number

    def decrypt_data(self, encrypted_data, received_packet_number):
        if received_packet_number <= self.last_received_packet_number:
            raise Exception("Replay attack detected. Discarding packet.")
        self.last_received_packet_number = received_packet_number
        nonce = self.construct_nonce(received_packet_number)
        cipher = AES.new(self.session_key, AES.MODE_CTR, nonce=nonce)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data

    def derive_session_key(self):
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'session_key',
        ).derive(self.shared_secret)

    def construct_nonce(self, packet_number):
        pn_bytes = packet_number.to_bytes(6, byteorder='big')
        nonce = self.priority + self.source_mac + pn_bytes
        return nonce

    def verify_certificate(self, certificate):
        current_time = datetime.now(timezone.utc)

        try:
            not_valid_before = certificate.not_valid_before_utc
            not_valid_after = certificate.not_valid_after_utc
        except AttributeError:
            not_valid_before = certificate.not_valid_before.replace(
                tzinfo=timezone.utc)
            not_valid_after = certificate.not_valid_after.replace(
                tzinfo=timezone.utc)

        if current_time < not_valid_before or current_time > not_valid_after:
            print(f"{self.name}: Certificate is expired or not yet valid.")
            self.generate_signing_key_pair()
            self.create_certificate()
            self.save_certificate_and_keys()
            print(f"{self.name}: Generated new certificate.")
        else:
            ca_public_key = self.ca.ca_certificate.public_key()
            try:
                ca_public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    asym_padding.PKCS1v15(),
                    certificate.signature_hash_algorithm,
                )
                print(f"{self.name}: Certificate verified successfully.")
            except InvalidSignature:
                print("Invalid signature")

    def verify_signature(self, signature, data):
        peer_public_key = self.peer_certificate.public_key()
        try:
            peer_public_key.verify(signature, data, asym_padding.PKCS1v15(),
                                   hashes.SHA256())
            print(f"{self.name}: Signature verified.")
        except InvalidSignature:
            print("Invalid signature")


def main():
    ca = CertificateAuthority()
    alice = Participant("Alice", ca)
    bob = Participant("Bob", ca)

    print("\n--- Protocol Execution ---\n")
    # Message 1: Alice sends initial DH parameters and key to Bob
    message_one = alice.send_message(alice.dh_public_key,
                                     "Bob",
                                     message_type="protocol")
    bob.receive_message(message_one, "Alice", message_type="protocol")

    # Message 2: Bob responds to Alice
    message_two = bob.send_message(bob.dh_public_key,
                                   "Alice",
                                   message_type="protocol")
    alice.receive_message(message_two, "Bob", message_type="protocol")

    # Message 3: Alice finalizes the handshake with Bob
    message_three = alice.send_message(alice.dh_public_key,
                                       "Bob",
                                       message_type="protocol")
    bob.receive_message(message_three, "Alice", message_type="protocol")

    print("\n--- Encrypted Message Exchange ---\n")
    # Encrypted message exchange between Alice and Bob
    alice_message = input("Alice, enter your message to Bob: ")
    encrypted_message_to_bob = alice.send_message(alice_message,
                                                  "Bob",
                                                  message_type="encrypted")
    bob.receive_message(encrypted_message_to_bob,
                        "Alice",
                        message_type="encrypted")

    bob_message = input("Bob, enter your message to Alice: ")
    encrypted_message_to_alice = bob.send_message(bob_message,
                                                  "Alice",
                                                  message_type="encrypted")
    alice.receive_message(encrypted_message_to_alice,
                          "Bob",
                          message_type="encrypted")


if __name__ == "__main__":
    main()
