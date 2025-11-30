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

# --- BLOCKCHAIN MEMORY (THE LEDGER) ---
blockchain_ledger = []

class Transaction:
    def __init__(self, sender_addr, sender_priv_key, recipient_addr, asset_hash, details, product_type): # main constructor function with the correct variables
        self.sender_address = sender_addr # creates the sender address variable
        self.sender_private_key = sender_priv_key # creates the private key variable
        self.recipient_address = recipient_addr # creates the recipient address variable
        self.asset_hash = asset_hash # creates the digital asset hash variable
        self.asset_details = details # creates the digital asset details variable
        self.product_type = product_type # creates the product type variable
        
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) # UPDATED: Saves time as a readable string (Year-Month-Day Hour:Minute:Second)

    # function that returns the address to the dictionary
    def to_dict(self):
        # returns the variables below
        return OrderedDict({
            'sender_address': self.sender_address, # returns the sender address
            'recipient_address': self.recipient_address, # returns the recipient address
            'asset_hash': self.asset_hash, # returns the asset hash
            'asset_details': self.asset_details, # returns the asset details
            'product_type': self.product_type, # returns the product type
            'timestamp': self.timestamp # returns the saved time
        })
    
    # function to sign the transaction
    def sign_transaction(self):
        # tries the signing the 
        try:
            # converts the key to binary
            priv_to_bin = RSA.importKey(binascii.unhexlify(self.sender_private_key))
            # creates a signer object which uses the binary private key
            signer = PKCS1_v1_5.new(priv_to_bin)
            
            # puts together the information into a single string to sign
            payload = (str(self.sender_address) + str(self.recipient_address) + str(self.asset_hash) + str(self.asset_details) + str(self.product_type) + str(self.timestamp)).encode('utf8')
            
            # creates a hash using SHA256
            h = SHA256.new(payload)
            # returns the signed signature converted to ASCII
            return binascii.hexlify(signer.sign(h)).decode('ascii')
        # exception occurs if an error occurs in the signing
        except Exception as e:
            logging.error(f"failed signing: {e}")
            return None

# --- Routes ---

@app.route('/')
def index():
    return render_template('client_wallet.html') # uses the client_wallet.html template created

@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transactions.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('view_transaction.html', transactions=blockchain_ledger)

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    # attempts to see if a new wallet can be created
    try:
        # sets key size to 2048
        key_size = 2048
        private_key = RSA.generate(key_size)
        public_key = private_key.publickey()
        
        response = {
            'private_key': binascii.hexlify(private_key.exportKey(format('DER'))).decode('ascii'),
            'public_key': binascii.hexlify(public_key.exportKey(format('DER'))).decode('ascii')
        }
        
        logging.info("New wallet successfully generated!")
        return jsonify(response), 200
    # exception if there is an error generating the wallet
    except Exception as e:
        # logs the error
        logging.error(f"Generating wallet failure: {e}")
        # returns an error message to the user
        return jsonify({"error": "Wallet generation failed"}), 500

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    # makes sure that the following variables are included so the transaction can be generated
    required = ['sender_address', 'sender_private_key', 'recipient_address', 'asset_hash', 'asset_details', 'product_type']
    # if statement to see if not every required variable is present
    if not all(k in request.form for k in required):
        # returns error message notifying of the missing variable
        return jsonify({'error': 'Required transaction value is missing.'}), 400

    # attempts to successfully generate the transaction
    try:
        sender_address = request.form['sender_address'] # requests from the sender_address variable
        sender_private_key = request.form['sender_private_key'] # requests from the sender_private_key variable
        recipient_address = request.form['recipient_address'] # requests from the recipient_address variable
        asset_hash = request.form['asset_hash'] # requests from the asset_hash variable
        asset_details = request.form['asset_details'] # requests from the asset_details variable
        product_type = request.form['product_type'] # requests from the product_type variable

        # for statement to check for detail duplication
        for block in blockchain_ledger:
            # if statment to see if the block for asset_details is the same
            if block['asset_details'] == asset_details:
                # logs a warning of duplication
                logging.warning(f"failed duplication attempt: {asset_details}")
                # returns an error stating there was a duplication
                return jsonify({'error': 'Product with the same name already exists!'}), 400

        # variable that sends the variables to the transaction class
        new_tx = Transaction(sender_address, sender_private_key, recipient_address, asset_hash, asset_details, product_type)
        
        # variable with the signed signature information
        signature = new_tx.sign_transaction()
        # if statement to see if there is no signature
        if signature is None:
            # returns an error saying private key was wronf
            return jsonify({'error': 'Invalid private key'}), 400

        # new variable holding the signed transaction information making it dictionary format
        tx_data = new_tx.to_dict()
        # ledger appends the data
        blockchain_ledger.append(tx_data)

        # response holding the transaciton and signature
        response = {
            'transaction': tx_data, # represents the transaction variable
            'signature': signature # represents the signature variable
        }
        
        # logs the registered asset
        logging.info(f"Asset has been registered: {asset_details}")
        # returns the response
        return jsonify(response), 200
        
    # exception for an error
    except Exception as e:
        # logs the transaction error
        logging.error(f"Transaction error: {e}")
        # returns the error to the user
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help='port to listen on')
    args = parser.parse_args()
    
    app.run(host='0.0.0.0', port=args.port, debug=True)
