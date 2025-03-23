import serial
import time
import base58
from solana.rpc.api import Client
from solana.transaction import Transaction, Signature
from solders.system_program import TransferParams, transfer
from solders.pubkey import Pubkey
import qrcode

# Initialize Serial Connection
serial_port = "/dev/tty.usbserial-220"  # Update with your actual port
baud_rate = 115200

print(f"[INFO] Connecting to Arduino on {serial_port} at {baud_rate} baud...")
ser = serial.Serial(serial_port, baud_rate)
time.sleep(0.5)  # Allow time for the connection to establish
print("[INFO] Connection established with Arduino.")


while True:
    # Menu
    print("1. Transfer SOL")
    print("2. Solana Public key")
    print("3. Exit")
    print("4. Ethereum Public key")
    choice = input("Enter your choice: ")

    if choice == "1":
        # Ask for receiver address and amount
        receiver_address = input("Receiver Address: ")
        amount = int(float(input("Amount (in SOL): ")) * 1000000000)  # Convert to lamports   

        # Initialize Solana RPC
        print("[INFO] Connecting to Solana RPC...")
        rpc = Client("https://api.devnet.solana.com")

        # Create a transaction and add the instruction
        transaction = Transaction()

        # Get the latest blockhash
        print("[INFO] Fetching latest Solana blockhash...")
        blockhash_resp = rpc.get_latest_blockhash()
        blockhash = blockhash_resp.value.blockhash
        transaction.recent_blockhash = blockhash

        # Send it a "1" so it knows to expect a transaction
        ser.write(b"1")

        # Wait for the Arduino to send back the public key
        while True:
            s_pubkey = ser.readline().strip()
            if s_pubkey.startswith(b"Pubkey:"):
                s_pubkey = s_pubkey.replace(b"Pubkey:", b"").strip()
                break

        print(f"[INFO] Pubkey: {s_pubkey.decode()}")

        # Define sender and receiver public keys
        sender_pub = Pubkey(base58.b58decode(s_pubkey.decode()))
        receiver_pub = Pubkey(base58.b58decode(receiver_address))

        # Create a transfer instruction
        transfer_instruction = transfer(
            TransferParams(
                from_pubkey=sender_pub,
                to_pubkey=receiver_pub,
                lamports=amount,
            )
        )
        transaction.add(transfer_instruction)


        # Serialize the transaction message
        serialized_message = transaction.serialize_message()

        # Send the serialized transaction message to the Arduino
        print("[INFO] Sending transaction to Arduino for signing...")
        ser.write(serialized_message.hex().encode() + b"\n")
        print(f"[INFO] Transaction: {serialized_message.hex().encode()}")

        # Wait for the Arduino to send back the signature
        while True:
            line = ser.readline().strip()
            if line.startswith(b"Signature (Base58):"):
                signature_base58 = line.split(b":")[1].strip().decode()
                break

        # Decode the Base58 signature
        signature_bytes = base58.b58decode(signature_base58)
        print(f"[INFO] Signature: {signature_base58}")

        # Ensure signature is valid
        assert len(signature_bytes) == 64, "[ERROR] Invalid signature length"

        # Create a Signature object
        signature = Signature(signature_bytes)

        # Add the signature to the transaction
        transaction.add_signature(sender_pub, signature)

        # Send the signed transaction
        print("[INFO] Sending the signed transaction to Solana RPC...")
        response = rpc.send_raw_transaction(transaction.serialize())

        # Output transaction result
        import json
        response_json = json.loads(response.to_json())
        print(f"[SUCCESS] Transaction sent! Signature: {response_json['result']}")
        print(f"[SUCCESS] Solscan: https://solscan.io/tx/{response_json['result']}?cluster=devnet")

    elif choice == "2":
        # Send it a "2" so it knows to expect an account info request
        ser.write(b"2")

        # Wait for the Arduino to send back the public key
        while True:
            s_pubkey = ser.readline().strip()
            if s_pubkey.startswith(b"Pubkey:"):
                s_pubkey = s_pubkey.replace(b"Pubkey:", b"").strip()
                break

        print(f"[INFO] Solana Public key: {s_pubkey.decode()}")
        # Press 1 to open a qr code for the pubkey and any other key to close
        qr = input("(1) for QR code: ")
        if qr == "1":
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,  # Highest error correction level
                box_size=10,
                border=4,
            )
            qr.add_data(s_pubkey.decode())
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.show()
            
    elif choice == "3":
        break
    elif choice == "4":
        ser.write(b"4")
        # Wait for the Arduino to send back the public key
        while True:
            s_pubkey = ser.readline().strip()
            if s_pubkey.startswith(b"Pubkey:"):
                s_pubkey = s_pubkey.replace(b"Pubkey:", b"").strip()
                break

        print(f"[INFO] Ethereum Public key: {s_pubkey.decode()}")
        
        qr = input("(1) for QR code: ")
        if qr == "1":
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,  # Highest error correction level
                box_size=10,
                border=4,
            )
            qr.add_data(s_pubkey.decode())
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.show()
        