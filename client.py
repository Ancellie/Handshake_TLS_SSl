from crypto_utils import (
    generate_random_bytes,
    deserialize_public_key,
    rsa_encrypt,
    generate_session_key,
    aes_encrypt,
    aes_decrypt
)


class Client:

    def __init__(self):
        self.client_random = None
        self.server_random = None
        self.server_public_key = None
        self.premaster_secret = None
        self.session_key = None
        self.handshake_complete = False

    def step1_send_client_hello(self):
        print("\n[CLIENT] Sending ClientHello...")

        self.client_random = generate_random_bytes(32)
        print(f"   Client Random: {self.client_random.hex()[:32]}...")

        return self.client_random

    def step2_receive_server_hello(self, server_hello):
        print("\n[CLIENT] Received ServerHello")

        self.server_random = server_hello['server_random']
        print(f"   Server Random: {self.server_random.hex()[:32]}...")

        self.server_public_key = deserialize_public_key(server_hello['public_key'])
        print("   Server public key received")

    def step3_send_premaster_secret(self):
        print("\n[CLIENT] Generating PreMaster Secret...")

        self.premaster_secret = generate_random_bytes(48)
        print(f"   PreMaster: {self.premaster_secret.hex()[:32]}...")

        encrypted_premaster = rsa_encrypt(self.server_public_key, self.premaster_secret)
        print("   Encrypted with server's public key")

        return encrypted_premaster

    def step5_generate_session_key(self):
        print("\n[CLIENT] Generating session key...")
        self.session_key = generate_session_key(
            self.client_random,
            self.server_random,
            self.premaster_secret
        )
        print(f"   Session Key: {self.session_key.hex()[:32]}...")

    def step6_send_client_finished(self):
        print("\n[CLIENT] Sending 'Client finished'...")
        message = "Client finished! Waiting for confirmation."
        encrypted = aes_encrypt(self.session_key, message)
        return encrypted

    def step6_verify_server_finished(self, encrypted_message):
        print("\n[CLIENT] Verifying 'Finished' message from server...")

        try:
            message = aes_decrypt(self.session_key, encrypted_message)
            print(f"   Decrypted: '{message}'")

            if "Server finished" in message:
                print("   Server verified!")
                self.handshake_complete = True
                return True
        except Exception as e:
            print(f"   Error: {e}")
        return False

    def send_message(self, message):
        if not self.handshake_complete:
            raise Exception("Handshake not complete!")
        return aes_encrypt(self.session_key, message)

    def receive_message(self, encrypted_message):
        if not self.handshake_complete:
            raise Exception("Handshake not complete!")
        return aes_decrypt(self.session_key, encrypted_message)