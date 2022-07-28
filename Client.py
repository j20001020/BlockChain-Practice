import pickle
import socket
import sys
import threading
import time
import rsa

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender
        self.receiver - receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message

# 初始化交易
def initialize_transaction(sender, receiver, amounts, fee, message):
    # No need to check balance
    new_transaction = Transaction(sender, receiver, amounts, fee, message)
    return new_transaction

def transaction_to_string(transaction):
    transaction_dict = {
        'sender': str(transaction.sender),
        'receiver': str(transaction.receiver),
        'amounts': transaction.amounts,
        'fee': transaction.fee,
        'message': transaction.message
    }
    return str(transaction_dict)

# 簽章交易
def sign_transaction(transaction, private):
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private
    private_key += '\n-----END RSA PRIVATE KEY-----\n'
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode("utf-8"))
    transaction_str = transaction_to_string(transaction)
    signature = rsa.sign(transaction_str.encode("utf-8"), private_key_pkcs, 'SHA-1')
    return signature

# 接收訊息
def handle_receive():
    while True:
        response = client.recv(4096)
        if response:
            print(f"[*] Message from node: {response}")

# 產生錢包地址與公私鑰
def generate_address():
    public, private = rsa.newkeys(512)
    public_key = public.save_pkcs1()
    private_key = private.save_pkcs1()
    return get_address_from_public(public_key),extract_from_private(private_key)

def get_address_from_public(public):
    address = str(public).replace('\\n','')
    address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
    address = address.replace("-----END RSA PUBLIC KEY-----'", '')
    address = address.replace(' ', '')
    return address

def extract_from_private(private):
    private_key = str(private).replace('\\n', '')
    private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
    private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
    private_key = private_key.replace(' ', '')
    return private_key

if __name__ == '__main__':
    target_host = "192.168.197.1"
    target_port = int(sys.argv[1])
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))

    receive_handler = threading.Thread(target=handle_receive)
    receive_handler.start()

    # client流程
    # 1.產生地址與公私鑰
    # 2.向節點詢問帳戶的餘額
    # 3.發起並簽署交易後送到節點端等待礦工確認與上鏈
    command_dict = {
        "1": "generate_address",
        "2": "get_balance",
        "3": "transaction"
    }

    while True:
        print("Command list: ")
        print("1. Generate Address")
        print("2. Get Balance")
        print("3. Transaction")
        command = input("Command: ")

        if str(command) not in command_dict.keys():
            print("Unknown command.")
            continue

        message = {
            "request": command_dict[str(command)]
        }

        if message["request"] == "generate_address":
            address, private_key = generate_address()
            print(f"Address: {address}")
            print(f"Private key {private_key}:")
        elif message["request"] == "get_balance":
            address = input("Address: ")
            message["address"] = address
            client.send(pickle.dumps(message))
        elif message["request"] == "transaction":
            address = input("Address: ")
            private_key = input("Private_key: ")
            receiver = input("Receiver: ")
            amounts = input("Amounts: ")
            fee = input("Fee: ")
            remark = input("Remark: ")
            new_transaction = initialize_transaction(address, receiver, int(amounts), int(fee), remark)
            signature = sign_transaction(new_transaction, private_key)
            message["transaction"] = new_transaction
            message["signature"] = signature

            client.send(pickle.dumps(message))

        else:
            print("Unknown command.")
        time.sleep(1)
