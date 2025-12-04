from crypto_utils import (
    generate_random_bytes,
    generate_rsa_keys,
    serialize_public_key,
    rsa_decrypt,
    generate_session_key,
    aes_encrypt,
    aes_decrypt
)


class Server:
    def __init__(self):
        self.server_random = None
        self.client_random = None
        self.private_key = None
        self.public_key = None
        self.premaster_secret = None
        self.session_key = None
        self.handshake_complete = False

    def step1_receive_client_hello(self, client_random):
        print("\n[SERVER] Received ClientHello")
        print(f"   Client Random: {client_random.hex()[:32]}...")
        self.client_random = client_random

    def step2_send_server_hello(self):
        print("\n[SERVER] Generating ServerHello...")

        self.server_random = generate_random_bytes(32)
        print(f"   Server Random: {self.server_random.hex()[:32]}...")

        self.private_key, self.public_key = generate_rsa_keys()
        print("   RSA keys generated (2048 bit)")

        return {
            'server_random': self.server_random,
            'public_key': serialize_public_key(self.public_key)
        }

    def step4_receive_premaster_secret(self, encrypted_premaster):
        print("\n[SERVER] Received encrypted PreMaster Secret")

        self.premaster_secret = rsa_decrypt(self.private_key, encrypted_premaster)
        print(f"   Decrypted: {self.premaster_secret.hex()[:32]}...")

    def step5_generate_session_key(self):
        print("\n[SERVER] Generating session key...")
        self.session_key = generate_session_key(
            self.client_random,
            self.server_random,
            self.premaster_secret
        )
        print(f"   Session Key: {self.session_key.hex()[:32]}...")

    def step6_verify_client_finished(self, encrypted_message):
        print("\n[SERVER] Verifying 'Finished' message from client...")

        try:
            message = aes_decrypt(self.session_key, encrypted_message)
            print(f"   Decrypted: '{message}'")

            if "Client finished" in message:
                print("   Client verified!")
                return True
        except Exception as e:
            print(f"   Error: {e}")
        return False

    def step6_send_server_finished(self):
        print("\n[SERVER] Sending 'Server finished'...")
        message = "Server finished!  Handshake complete."
        encrypted = aes_encrypt(self.session_key, message)
        self.handshake_complete = True
        print("   Handshake complete!")
        return encrypted

    def send_message(self, message):
        if not self.handshake_complete:
            raise Exception("Handshake not complete!")
        return aes_encrypt(self.session_key, message)

    def receive_message(self, encrypted_message):
        if not self.handshake_complete:
            raise Exception("Handshake not complete!")
        return aes_decrypt(self.session_key, encrypted_message)