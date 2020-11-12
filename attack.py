
import bcrypt
import os
import base64
import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import codecs
import time


hashes = [{"name": 'md5', "code": '0'}, {"name": 'md5_static_salt', "code": '10'}, {
    "name": 'md5_dynamic_salt', 'code': '10'}, {"name": 'ml', "code": '1000'}, {'name': 'sha512_crypt', 'code': '1800'}]

print('Bienvenido al menu de des-encriptado de hashes, seleccione el numero del archivo que desee des-encriptar:', "\n")

print('1. MD5.txt\n')
print('2. MD5_STATIC_SALT.txt\n')
print('3. MD5_DYNAMIC_SALT.txt\n')
print('4. ML.txt\n')
print('5. SHA512_CRYPT.txt\n')

hash_type = int(input(''))

while((bool(hash_type != 1) ^ bool(hash_type != 2) ^ bool(hash_type != 3) ^ bool(hash_type != 4) ^ bool(hash_type != 5))):
    print('Opcion no valida, porfavor intente nuevamente.\n')
    print('Bienvenido al menu de des-encriptado de hashes, seleccione el numero del archivo que desee des-encriptar:', "\n")
    print('1. MD5.txt\n')
    print('2. MD5_STATIC_SALT.txt\n')
    print('3. MD5_DYNAMIC_SALT.txt\n')
    print('4. ML.txt\n')
    print('5. SHA512_CRYPT.txt\n')

    hash_type = int(input(''))

hash_type = hashes[hash_type - 1]


os.system('cd hashcat & hashcat.exe -m {} -a 0 Hashes\{}.txt diccionarios\diccionario_2.txt --force --outfile=../output/{}_text.txt --outfile-format 2'.format(
    hash_type["code"], hash_type["name"], hash_type['name']))

fileHash = open("output/{}_text.txt".format(hash_type['name']), "r")


hash_files = input('Desea hashear los archivos con bcrypt? Y/N\n')

if hash_files == 'Y':
    file_object = open("hashed/{}_hashed.txt".format(hash_type['name']), "w")
    start_time = time.time()
    for hash in fileHash:
        pwd = bytes(hash, 'utf-8')
        hashed = bcrypt.hashpw(pwd, bcrypt.gensalt())
        hashed = hashed.decode('utf-8')
        hashed += '{}\n'.format(hashed)
        file_object.write(hashed)
    file_object.write("--- %s seconds ---" % (time.time() - start_time))
    file_object.close()

fileHash.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 3000))


while True:
    s.sendall(bytes(hash_type['name'], 'utf-8'))
    full_msg = input('Ingrese su mensaje hacia el server\n')
    s.sendall(bytes(full_msg, 'utf-8'))

    if full_msg == 'exit':
        break

    elif full_msg == 'key':
        # hashedFile = open('md5_hashed.txt', 'r')
        received_message = s.recv(1024)
        new_file = open(
            "rehashed/{}_rehashed.txt".format(hash_type['name']), "w")
        file_with_hashes = open(
            'hashed/{}_hashed.txt'.format(hash_type['name']), 'r')
        key = RSA.importKey(open(received_message.decode('utf-8')).read())

        cipher = PKCS1_OAEP.new(key)
        for hash in file_with_hashes:
            message = bytes(hash, 'utf-8')
            ciphertext = cipher.encrypt(message)
            new_file.write(ciphertext.hex().upper()+'\n')
        file_with_hashes.close()
        new_file.close()
        s.sendall(
            bytes('rehashed/{}_rehashed.txt'.format(hash_type['name']), 'utf-8'))

    else:
        received_message = s.recv(1024)
        print(received_message.decode('utf-8'))
s.close()
