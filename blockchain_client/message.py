import binascii
import logging
import time
from collections import OrderedDict

from flask import Flask, render_template, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

app = Flask(__name__)

blockchain_ledger = []

class Transaction:
    def __init__(self, sender_addr, sender_priv_key, recipient_addr, asset_hash, details, product_type):
        self.sender_address = sender_addr
        self.sender_private_key = sender_priv_key
        self.recipient_address = recipient_addr
        self.asset_hash = asset_hash
        self.asset_details = details
        self.product_type = product_type
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    def to_dict(self):
        return OrderedDict({
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'asset_hash': self.asset_hash,
            'asset_details': self.asset_details,
            'product_type': self.product_type,
            'timestamp': self.timestamp
        })
    
    def sign_transaction(self):
        try:
            private_key_obj = RSA.importKey(binascii.unhexlify(self.sender_private_key))
            signer = PKCS1_v1_5.new(private_key_obj)
            
            payload = (str(self.sender_address) + str(self.recipient_address) + 
                       str(self.asset_hash) + str(self.asset_details) + 
                       str(self.product_type) + str(self.timestamp)).encode('utf8')
            
            h = SHA256.new(payload)
            return binascii.hexlify(signer.sign(h)).decode('ascii')
        except Exception as e:
            logging.error(f"Signing failed: {e}")
            return None

@app.route('/')
def index():
    return render_template('client_wallet.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transactions.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('view_transaction.html', transactions=blockchain_ledger)

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    try:
        key_size = 2048
        private_key = RSA.generate(key_size)
        public_key = private_key.publickey()
        
        response = {
            'private_key': binascii.hexlify(private_key.exportKey(format('DER'))).decode('ascii'),
            'public_key': binascii.hexlify(public_key.exportKey(format('DER'))).decode('ascii')
        }
        
        logging.info("New wallet identity generated successfully.")
        return jsonify(response), 200
    except Exception as e:
        logging.error(f"Error generating wallet: {e}")
        return jsonify({"error": "Wallet generation failed"}), 500

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    required = ['sender_address', 'sender_private_key', 'recipient_address', 'asset_hash', 'asset_details', 'product_type']
    if not all(k in request.form for k in required):
        return jsonify({'error': 'Missing transaction values'}), 400

    try:
        sender_address = request.form['sender_address']
        sender_private_key = request.form['sender_private_key']
        recipient_address = request.form['recipient_address']
        asset_hash = request.form['asset_hash']
        asset_details = request.form['asset_details']
        product_type = request.form['product_type']

        for block in blockchain_ledger:
            if block['asset_details'] == asset_details:
                logging.warning(f"Duplicate attempt rejected: {asset_details}")
                return jsonify({'error': 'REJECTED: A product with this name already exists on the blockchain!'}), 400

        new_tx = Transaction(sender_address, sender_private_key, recipient_address, asset_hash, asset_details, product_type)
        
        signature = new_tx.sign_transaction()
        if signature is None:
            return jsonify({'error': 'Invalid Private Key'}), 400

        tx_data = new_tx.to_dict()
        blockchain_ledger.append(tx_data)

        response = {
            'transaction': tx_data,
            'signature': signature
        }
        
        logging.info(f"New Asset Registered: {asset_details}")
        return jsonify(response), 200
        
    except Exception as e:
        logging.error(f"Transaction Error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help='port to listen on')
    args = parser.parse_args()
    
    app.run(host='0.0.0.0', port=args.port, debug=True)
