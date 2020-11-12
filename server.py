import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import codecs
import sqlite3

hashes = [{"name": 'md5', "code": '0'}, {"name": 'md5_static_salt', "code": '10'}, {
    "name": 'md5_dynamic_salt', 'code': '10'}, {"name": 'ml', "code": '1000'}, {'name': 'sha512_crypt', 'code': '1800'}]

key = RSA.generate(2048)

private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey()

exported_key = public_key.export_key()
array_key = exported_key.decode('utf-8').split('\n')
cuted_key = ''
for x in range(1, len(array_key) - 1):
    cuted_key += array_key[x]

file_out = open("receiver.pem", "wb")
file_out.write(exported_key)
file_out.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), 3000))
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.listen(1)
clientsocket, address = s.accept()

file_hash = clientsocket.recv(300).decode('utf-8')
while True:
    try:
        print("connected from ", address)
        received_message = clientsocket.recv(300).decode('utf-8')
        if received_message == 'exit':
            break
        elif received_message == 'key':
            clientsocket.sendall(bytes('receiver.pem', 'utf-8'))
            hashed_file_route = clientsocket.recv(300).decode('utf-8')

            hashed_file = open(hashed_file_route, 'r')

            unhashed_file = open('unhashed/{}_unhashed'.format(file_hash), 'w')
            key = RSA.importKey(open('private.pem').read())
            cipher = PKCS1_OAEP.new(key)
            for hash_line in hashed_file:
                message = cipher.decrypt(bytes.fromhex(hash_line))
                unhashed_file.write(message.decode('utf-8'))

            unhashed_file.close()

            unhashed_file = open('unhashed/{}_unhashed'.format(file_hash), 'r')

            connection = sqlite3.connect('sqlite/{}.sqlite'.format(file_hash))
            cur = connection.cursor()
            cur.execute('CREATE TABLE HASH (bcrypt_hash VARCHAR)')

            for hashs in unhashed_file:
                cur.execute(
                    'INSERT INTO HASH (bcrypt_hash) VALUES (?)', ([hashs]))
                connection.commit()
            unhashed_file.close()
            connection.close()

            hashed_file.close()

    except KeyboardInterrupt:
        if clientsocket:  # <---
            clientsocket.close()
        break  # <---
s.close()
clientsocket.close()
