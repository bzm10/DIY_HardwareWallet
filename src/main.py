import serial
import time
import base58
from solana.rpc.api import Client
from solana.transaction import Transaction, Signature
from solders.system_program import TransferParams, transfer
from solders.pubkey import Pubkey

# Initialize Serial Connection
serial_port = "/dev/tty.usbserial-220"  # Update with your actual port
baud_rate = 115200

print(f"[INFO] Connecting to Arduino on {serial_port} at {baud_rate} baud...")
ser = serial.Serial(serial_port, baud_rate)
time.sleep(2)  # Allow time for the connection to establish
print("[INFO] Connection established with Arduino.")

# Initialize Solana RPC
print("[INFO] Connecting to Solana RPC...")
rpc = Client("https://api.devnet.solana.com")

# Define sender and receiver public keys
print("[INFO] Setting up sender and receiver public keys...")
sender_pub = Pubkey(base58.b58decode("7pKXWei9ukBDJsjARPVeebgr3W41EkchFpPtcwZDTV2X"))
receiver_pub = Pubkey(base58.b58decode("6quXCrE14shQpG2AmMctUkgQu54AcarsiSTTRRSc2fo4"))

# Amount to transfer (in lamports)
amount = 100000  # 0.0001 SOL
print(f"[INFO] Preparing transaction: Sending {amount} lamports.")

# Create a transfer instruction
transfer_instruction = transfer(
    TransferParams(
        from_pubkey=sender_pub,
        to_pubkey=receiver_pub,
        lamports=amount,
    )
)

# Create a transaction and add the instruction
transaction = Transaction()
transaction.add(transfer_instruction)

# Get the latest blockhash
print("[INFO] Fetching latest Solana blockhash...")
blockhash_resp = rpc.get_latest_blockhash()
blockhash = blockhash_resp.value.blockhash
transaction.recent_blockhash = blockhash
print(f"[INFO] Blockhash fetched: {blockhash}")

# Serialize the transaction message
serialized_message = transaction.serialize_message()
print(f"[DEBUG] Serialized transaction message (bytes): {serialized_message.hex()}")

# Send the serialized transaction message to the Arduino
print("[INFO] Sending serialized transaction message to Arduino...")
ser.write(serialized_message.hex().encode())

# Wait for the Arduino to send back the signature
print("[INFO] Waiting for Arduino to return the signed transaction...")
while True:
    line = ser.readline().strip()
    print(f"[DEBUG] Received from Arduino: {line}")
    
    if line.startswith(b"Signature (Base58):"):
        signature_base58 = line.split(b":")[1].strip().decode()
        print(f"[INFO] Received signed transaction from Arduino: {signature_base58}")
        break

# Decode the Base58 signature
print("[INFO] Decoding received Base58 signature...")
signature_bytes = base58.b58decode(signature_base58)
print(f"[DEBUG] Decoded signature bytes: {signature_bytes.hex()}")

# Ensure signature is valid
assert len(signature_bytes) == 64, f"[ERROR] Invalid signature length: Expected 64, got {len(signature_bytes)}"

# Create a Signature object
signature = Signature(signature_bytes)

# Add the signature to the transaction
print("[INFO] Adding the signature to the transaction...")
transaction.add_signature(sender_pub, signature)


# Send the signed transaction
print("[INFO] Sending the signed transaction to Solana RPC...")
response = rpc.send_raw_transaction(transaction.serialize())

# Output transaction result
print(f"[SUCCESS] Transaction sent! Signature: {response.to_json()['result']}")