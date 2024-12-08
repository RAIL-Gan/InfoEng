import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

run = True
server_pr = 0
server_pu = 0
client_pu = 0

def receiveMsg(conn):
    global run, client_pu
    try:
        spublic = (conn.recv(1024)).decode()
        received_pem = spublic.encode('utf-8')
        client_pu = serialization.load_pem_public_key(received_pem)
        print('Client Public key received')
    except socket.error as msg:
        run = False
    except KeyboardInterrupt:
        run = False

	
    while run:
        try:
            data = conn.recv(1024)
            if not data:
                continue
            plaintext = decryptMessage(data).decode("utf-8")
            print(f'\nMessage Received: {format(plaintext)} \nSend Message to client: ', end='')

        except socket.error as msg:
            run = False
        except KeyboardInterrupt:
            run = False

def decryptMessage(ciphertext):
    decrypted_msg = server_pr.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted_msg

def sendMessage(conn):
    global run, server_pu
    try:
        conn.sendall(server_pu.encode())
        print('Public key sent')
    except socket.error as err:
        run = False
    except KeyboardInterrupt:
        run = False

    while run:
        try:
            msg = input('Send Message to client: ')
            ciphertext = encryptMessage(msg.encode('utf-8'))
            conn.sendall(ciphertext)
            print('Message sent')
        except socket.error as err:
            run = False
        except KeyboardInterrupt:
            run = False

def encryptMessage(message):
    encrypted_msg = client_pu.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_msg

def listenConnection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('192.168.56.1', 6060))
    s.listen(1)
    conn, addr = s.accept()
    print('Server accepted client connection...')
    return conn, addr, s

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
    print("Happy")
    conn, addr, s = listenConnection()
    server_pr, server_pu = generateKeys()
    print("Happy")
    rcv = Thread(target=receiveMsg, args=(conn, ))
    rcv.start()
    sendMessage(conn)
