import pickle
import socket
import sys
import threading
import time
import hashlib
import rsa

class Transaction:
    def __init__(self,sender,receiver,amounts,fee,message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message

class Block:
    def __init__(self,previous_hash,difficulty,miner,miner_rewards):
        self.previous_hash = previous_hash
        self.hash = ''
        self.difficulty = difficulty
        self.nonce = 0
        self.timestamp = int(time.time())
        self.transactions = []
        self.miner = miner
        self.miner_rewards = miner_rewards

class BlockChain:
    def __init__(self):
        self.adjust_difficulty_blocks = 10
        self.difficulty = 1
        self.block_time = 30
        self.miner_rewards = 10
        self.block_limitation = 32
        self.chain = []
        self.pending_transactions = []

        # For P2P connection
        self.socket_host = "192.168.197.1"
        self.socket_port = int(sys.argv[1])
        self.start_socket_server()

    # 產生創世塊(genesis block)
    def create_genesis_block(self):
        print("Create genesis block...")
        new_block = Block('Zero in your target,and go for it.', self.difficulty, 'KAI', self.miner_rewards)
        new_block.hash = self.get_hash(new_block, 0)
        self.chain.append(new_block)

    # 把交易明細轉換成字串
    def transaction_to_string(self, transaction):
        transaction_dict = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
            'fee': transaction.fee,
            'message': transaction.message
        }
        return str(transaction_dict)

    # 把區塊紀錄的所有交易明細轉換成一個字串
    def get_transaction_string(self, block):
        transaction_str = ''
        for transaction in block.transactions:
            transaction_str += self.transaction_to_string(transaction)
        return transaction_str

    # 依據這四筆資料產生相對應的Hash
    def get_hash(self, block, nonce):
        s = hashlib.sha1()
        s.update(
            (
                    block.previous_hash
                    + str(block.timestamp)
                    + self.get_transaction_string(block)
                    + str(nonce)
            ).encode("utf-8")
        )
        h = s.hexdigest()
        return h

    # 將交易紀錄放入新區塊
    def add_transaction_to_block(self, block):
        # 在區塊容量範圍內取得較高手續費的交易
        self.pending_transactions.sort(key=lambda x: x.fee, reverse=True)
        if len(self.pending_transactions) > self.block_limitation:
            transaction_accepted = self.pending_transactions[:self.block_limitation]
            self.pending_transactions = self.pending_transactions[self.block_limitation:]
        else:
            transaction_accepted = self.pending_transactions
            self.pending_transactions = []
        block.transactions = transaction_accepted

    # 挖掘新區塊，採用Proof of Work(POW)的工作方法
    def mine_block(self, miner):
        start = time.process_time()

        last_block = self.chain[-1]
        new_block = Block(last_block.hash, self.difficulty, miner, self.miner_rewards)

        self.add_transaction_to_block(new_block)
        new_block.previous_hash = last_block.hash
        new_block.difficulty = self.difficulty
        new_block.hash = self.get_hash(new_block, new_block.nonce)

        while new_block.hash[0: self.difficulty] != '0' * self.difficulty:
            new_block.nonce += 1
            new_block.hash = self.get_hash(new_block, new_block.nonce)

        time_consumed = round(time.process_time() - start, 5)
        print(f"Hash found: {new_block.hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s")
        self.chain.append(new_block)

    # 調整挖掘難度
    def adjust_difficulty(self):
        if len(self.chain) % self.adjust_difficulty_blocks != 1:
            return self.difficulty
        elif len(self.chain) <= self.adjust_difficulty_blocks:
            return self.difficulty
        else:
            start = self.chain[-1*self.adjust_difficulty_blocks-1].timestamp
            finish = self.chain[-1].timestamp
            average_time_consumed = round((finish - start) / (self.adjust_difficulty_blocks), 2)
            if average_time_consumed > self.block_time:
                print(f"Average block time:{average_time_consumed}s. Lower the difficulty")
                self.difficulty -= 1
            else:
                print(f"Average block time:{average_time_consumed}s. High up the difficulty")
                self.difficulty += 1

    # 計算帳戶餘額
    def get_balance(self, account):
        balance = 100
        for block in self.chain:
            # Check miner reward
            miner = False
            if block.miner == account:
                miner = True
                balance += block.miner_rewards
            for transaction in block.transactions:
                if miner:
                    balance += transaction.fee
                if transaction.sender == account:
                    balance -= transaction.amounts
                    balance -= transaction.fee
                elif transaction.receiver == account:
                    balance += transaction.amounts
        return balance

    # 驗證區塊鏈，確認Hash
    def verify_blockchain(self):
        previous_hash = ''
        for idx, block in enumerate(self.chain):
            if self.get_hash(block, block.nonce) != block.hash:
                print("Error:Hash not matched!")
                return False
            elif previous_hash !=  block.previous_hash and idx:
                print("Error:Hash not matched to previous_hash!")
                return False
            previous_hash = block.hash
        print("Hash correct!")
        return True

    # 利用RSA加密產生公、私鑰與地址
    def generate_address(self):
        public, private = rsa.newkeys(512)
        public_key = public.save_pkcs1()
        private_key = private.save_pkcs1()
        return self.get_address_from_public(public_key), private_key

    def get_address_from_public(self, public):
        address = str(public).replace('\\n','')
        address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
        address = address.replace("-----END RSA PUBLIC KEY-----'", '')
        address = address.replace(' ', '')
        print('Address: ', address)
        return address

    # 初始化新交易
    def initialize_transaction(self, sender, receiver, amount, fee, message):
        if self.get_balance(sender) < amount + fee:
            print("Balance not enough!")
            return False
        new_transaction = Transaction(sender, receiver, amount, fee, message)
        return new_transaction

    # 使用私鑰簽署交易
    def sign_transaction(self, transaction, private_key):
        private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key)
        transaction_str = self.transaction_to_string(transaction)
        signature = rsa.sign(transaction_str.encode("utf-8"), private_key_pkcs, 'SHA-1')
        return signature

    # 驗證交易並將交易加入Pending Pool
    def add_transaction(self, transaction, signature):
        public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
        public_key += transaction.sender
        public_key += '\n-----END RSA PUBLIC KEY-----\n'
        public_key_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode("utf-8"))
        transaction_str = self.transaction_to_string(transaction)
        if transaction.fee + transaction.amounts > self.get_balance(transaction.sender):
            return False, "Balance not enough!"
        try:
            # 驗證發送者
            rsa.verify(transaction_str.encode("utf-8"), signature, public_key_pkcs)
            self.pending_transactions.append(transaction)
            return True, "Authorized successfully!"
        except Exception:
            return False, "RSA Verified wrong!"

    # 開thread監聽新連線與傳入訊息
    def start_socket_server(self):
        t = threading.Thread(target=self.wait_for_socket_connection)
        t.start()

    def wait_for_socket_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.socket_host, self.socket_port))
            s.listen()
            while True:
                connection, address = s.accept()

                client_handler = threading.Thread(
                    target=self.receive_socket_message,
                    args=(connection, address)
                )
                client_handler.start()

    # 接收訊息後處理
    def receive_socket_message(self, connection, address):
        with connection:
            print(f"Connected by: {address}")
            while True:
                message = connection.recv(1024)
                print(f"[*] Received: {message}")
                try:
                    parsed_message = pickle.loads(message)
                except Exception:
                    print(f"{message} cannot be parsed")
                if message:
                    if parsed_message["request"] == "get_balance":
                        print("Start to get the balance for client...")
                        address = parsed_message["address"]
                        balance = self.get_balance(address)
                        response = {
                            "address": address,
                            "balance": balance
                        }
                    elif parsed_message["request"] == "transaction":
                        print("Start to transaction for client...")
                        new_transaction = parsed_message["data"]
                        result, result_message = self.add_transaction(
                            new_transaction,
                            parsed_message["signature"]
                        )
                        response = {
                            "result": result,
                            "result_message": result_message
                        }
                    else:
                        response = {
                            "message": "Unknown command."
                        }
                    response_bytes = str(response).encode("utf-8")
                    connection.sendall(response_bytes)

    def start(self):
        address, private = self.generate_address()

        print(f"Miner address: {address}")
        print(f"Miner private: {private}")
        self.create_genesis_block()
        while True:
            self.mine_block(address)
            self.adjust_difficulty()
        # self.create_genesis_block()
        # while(True):
        #     # Step1: initialize a transaction
        #     transaction = blockchain.initialize_transaction(address, 'KAI', 1, 1, 'Test')
        #     if transaction:
        #         # Step2: Sign your transaction
        #         signature = blockchain.sign_transaction(transaction, private)
        #         # Step3: Send it to blockchain
        #         blockchain.add_transaction(transaction, signature)
        #     self.mine_block(address)
        #     print(self.get_balance(address))
        #     self.adjust_difficulty()

if __name__ == '__main__':
    blockchain = BlockChain()
    blockchain.start()

    # print("Insert fake transaction.")
    # fake_transaction = Transaction('test123', address, 100, 1, 'Test')
    # blockchain.chain[1].transactions.append(fake_transaction)
    # blockchain.mine_block(address)
    #
    # blockchain.verify_blockchain()
