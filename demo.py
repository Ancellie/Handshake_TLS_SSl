from client import Client
from server import Server


def print_separator(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def main():
    print_separator("TLS/SSL HANDSHAKE SIMULATION")

    client = Client()
    server = Server()

    print_separator("STEP 1: Client Hello")
    client_random = client.step1_send_client_hello()
    server.step1_receive_client_hello(client_random)

    print_separator("STEP 2: Server Hello")
    server_hello = server.step2_send_server_hello()
    client.step2_receive_server_hello(server_hello)

    print_separator("STEP 3-4: PreMaster Secret Exchange")
    encrypted_premaster = client.step3_send_premaster_secret()
    server.step4_receive_premaster_secret(encrypted_premaster)

    print_separator("STEP 5: Session Key Generation")
    client.step5_generate_session_key()
    server.step5_generate_session_key()

    print("\nKey verification:")
    print(f"   Client: {client.session_key.hex()[:32]}...")
    print(f"   Server: {server.session_key.hex()[:32]}...")

    if client.session_key == server.session_key:
        print("   KEYS MATCH!")
    else:
        print("   ERROR: Keys don't match!")
        return

    print_separator("STEP 6: Finished Messages Exchange")

    client_finished = client.step6_send_client_finished()
    server.step6_verify_client_finished(client_finished)

    server_finished = server.step6_send_server_finished()
    client.step6_verify_server_finished(server_finished)

    print_separator("STEP 7: SECURE DATA EXCHANGE")

    print("\nChat simulation:")
    print("-" * 40)

    messages = [
        ("Client", "Hello!  This is a secret message"),
        ("Server", "Hi! Got your message! "),
        ("Client", "Sending password: super_secret_123"),
        ("Server", "Password received.  Thanks for secure connection! "),
    ]

    for sender, message in messages:
        if sender == "Client":
            encrypted = client.send_message(message)
            decrypted = server.receive_message(encrypted)
            print(f"\n[CLIENT] sends: '{message}'")
            print(f"   Encrypted: {encrypted.hex()[:40]}...")
            print(f"   [SERVER] received: '{decrypted}'")
        else:
            encrypted = server.send_message(message)
            decrypted = client.receive_message(encrypted)
            print(f"\n[SERVER] sends: '{message}'")
            print(f"   Encrypted: {encrypted.hex()[:40]}...")
            print(f"   [CLIENT] received: '{decrypted}'")

    print_separator("FILE TRANSFER")

    file_content = """This is a secret document! 

Author: Secret Agent
Date: 2025-12-04

Important information:
- Access code: ALPHA-BRAVO-123
- Location: Kyiv, Ukraine
- Mission: Successfully completed! 
"""

    print(f"\nOriginal file:\n{'-' * 40}\n{file_content}\n{'-' * 40}")

    encrypted_file = client.send_message(file_content)
    print(f"\nEncrypted file ({len(encrypted_file)} bytes):")
    print(f"   {encrypted_file.hex()[:60]}...")

    decrypted_file = server.receive_message(encrypted_file)
    print(f"\nDecrypted file on server:\n{'-' * 40}\n{decrypted_file}\n{'-' * 40}")

    print_separator("DEMONSTRATION COMPLETE")
    print("\nTLS/SSL handshake successfully simulated!")
    print("   All data transferred securely using AES-256 symmetric encryption.\n")


if __name__ == "__main__":
    main()