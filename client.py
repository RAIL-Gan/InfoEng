import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

run = True
client_pr = 0
client_pu = 0
server_pu = 0

def receiveMsg(s):
    global run, server_pu
    try:
        spublic = (s.recv(1024)).decode()
        received_pem = spublic.encode('utf-8')
        server_pu = serialization.load_pem_public_key(received_pem)
        print('Server Public key received')
    except socket.error as msg:
        run = False
    except KeyboardInterrupt:
        run = False
    while run:
        try:
            data = s.recv(1024)
            if not data:
                continue
            plaintext = decryptMessage(data).decode("utf-8")
            print(f'\nMessage Received: {format(plaintext)} \nSend Message to server: ', end='')

        except socket.error as msg:
            run = False
        except KeyboardInterrupt:
            run = False

def decryptMessage(ciphertext):
    decrypted_msg = client_pr.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted_msg

def sendMessage(s):
    global run, client_pu
    try:
        s.sendall(client_pu.encode())
        print('Public key sent')
    except socket.error as err:
        run = False
    except KeyboardInterrupt:
        run = False

    while run:
        try:
            msg = input('Send Message to server: ')
            ciphertext = encryptMessage(msg.encode('utf-8'))
            s.sendall(ciphertext)
            print('Message sent')
        except socket.error as err:
            run = False
        except KeyboardInterrupt:
            run = False

def encryptMessage(message):
    encrypted_msg = server_pu.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_msg

def generateKeys():
    private_key = rsa.generate_private_key(
    	public_exponent=65537,
    	key_size=2048,
    )

    public_key = private_key.public_key()
    # Serialize the public key to PEM format for storage or sharing
    pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    pem_public_string = pem_public_key.decode('utf-8')

    return private_key, pem_public_string

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.56.1', 6060))
    print('Client connected to server...')

    client_pr, client_pu = generateKeys()
    print("Happy")
    rcv = Thread(target=receiveMsg, args=(s, ))
    rcv.start()
    sendMessage(s)