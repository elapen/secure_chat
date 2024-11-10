# app.py

from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room
from pymongo import MongoClient
from Crypto.Util import number
from Crypto.Cipher import AES
from hashlib import sha256
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)
mongodb_url = os.getenv("Mongodburl")
# MongoDB client setup
client = MongoClient(mongodb_url)
db = client['secure_chat']
users_collection = db['users']

# Global Diffie-Hellman parameters
p = number.getPrime(2048)
g = 2  # Generator

def generate_keys():
    """Generate private and public keys for Diffie-Hellman key exchange."""
    private_key = number.getRandomRange(1, p - 1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_secret(their_public_key, my_private_key):
    """Compute the shared secret using the other party's public key and own private key."""
    shared_secret = pow(their_public_key, my_private_key, p)
    return shared_secret

def derive_aes_key(shared_secret):
    """Derive an AES key from the shared secret."""
    shared_secret_bytes = str(shared_secret).encode('utf-8')
    aes_key = sha256(shared_secret_bytes).digest()
    return aes_key

def encrypt_message(aes_key, plaintext):
    """Encrypt a plaintext message using AES encryption."""
    cipher = AES.new(aes_key, AES.MODE_CFB)
    iv = cipher.iv
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return iv + ciphertext

def decrypt_message(aes_key, ciphertext):
    """Decrypt a ciphertext message using AES decryption."""
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    plaintext = cipher.decrypt(actual_ciphertext)
    return plaintext.decode('utf-8')

@app.route('/', methods=['GET', 'POST'])
def index():
    """Render the login page and handle user authentication."""
    if request.method == 'POST':
        username = request.form['username']
        # Store username in session
        session['username'] = username
        # Generate Diffie-Hellman keys
        private_key, public_key = generate_keys()
        session['private_key'] = private_key
        session['public_key'] = public_key
        # Save public key to the database
        users_collection.update_one(
            {'username': username},
            {'$set': {'public_key': str(public_key)}},
            upsert=True
        )
        return redirect(url_for('chat'))
    return render_template('index.html')

@app.route('/chat')
def chat():
    """Render the chat interface."""
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('chat.html',
                           username=session['username'],
                           private_key=session['private_key'],
                           public_key=session['public_key'],
                           p=p,
                           g=g)


@socketio.on('join')
def handle_join():
    """Handle a user joining the chat room."""
    username = session['username']
    join_room(username)

@socketio.on('send_message')
def handle_send_message(data):
    """Handle sending an encrypted message to another user."""
    recipient = data['recipient']
    message = data['message']  # Encrypted message from the client
    sender = session['username']
    iv = data['iv']
    sender_public_key = data['sender_public_key']

    # Send the encrypted message and associated data to the recipient
    emit('receive_message', {
        'sender': sender,
        'message': message,
        'iv': iv,
        'sender_public_key': sender_public_key
    }, room=recipient)


@socketio.on('receive_message')
def handle_receive_message(data):
    """Handle receiving an encrypted message from another user."""
    sender = data['sender']
    ciphertext = bytes.fromhex(data['message'])
    # Retrieve sender's public key
    sender_data = users_collection.find_one({'username': sender})
    if sender_data:
        sender_public_key = sender_data['public_key']
        # Compute shared secret and derive AES key
        shared_secret = compute_shared_secret(sender_public_key, session['private_key'])
        aes_key = derive_aes_key(shared_secret)
        # Decrypt the message
        plaintext = decrypt_message(aes_key, ciphertext)
        # Display the message
        emit('display_message', {
            'sender': sender,
            'message': plaintext
        }, room=session['username'])
@socketio.on('get_public_key')
def handle_get_public_key(data):
    recipient = data['recipient']
    recipient_data = users_collection.find_one({'username': recipient})
    if recipient_data:
        recipient_public_key = recipient_data['public_key']
        return {'success': True, 'public_key': recipient_public_key}
    else:
        return {'success': False}


if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)



