#local side / client
import json
from base64 import b64encode
from base64 import b64decode
import sys, socket, select
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import os
import hashlib
import signal

os.system("clear")
print ("""

         ____  ____  ____   __   _  _      __  ____   ___
        (    \(  _ \(  __) / _\ ( \/ ) ___(  )(  _ \ / __)
         ) D ( )   / ) _) /    \/ \/ \(___))(  )   /( (__
        (____/(__\_)(____)\_/\_/\_)(_/    (__)(__\_) \___)                  

                          Secure IRC by DreamSec
                              Dreamsec.club

""")

def sigint_handler(signum, frame):
    print ('\n[error] user interupt')
    print ("[info] shutting down DREAM-IRC \n\n")
    sys.exit()
signal.signal(signal.SIGINT, sigint_handler)

def hasher(key):
        hash_object = hashlib.sha512(key.encode("UTF-8"))
        hexd = hash_object.hexdigest()
        hash_object = hashlib.md5(hexd.encode("UTF-8"))
        hex_dig = hash_object.hexdigest()
        return hex_dig.encode("UTF-8")
def encrypt(key,data):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        json_input = json.dumps({'iv':iv, 'ciphertext':ct}) 
        return json_input
def decrypt(key,json_input):
        try:
                b64 = json.loads(json_input)
                iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ct), AES.block_size)
        except (ValueError, KeyError):
                print("Incorrect decryption")
                pt = ""
        return pt.decode()


def chat_client():
    if(len(sys.argv) < 5) :
        print ('python dream-irc.py [hostname] [port] [password] [usenrame]')
        sys.exit()

    host = sys.argv[1]
    port = int(sys.argv[2])
    key = sys.argv[3]
    key = hasher(key)
    uname = sys.argv[4]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)


    try :
        s.connect((host, port))

    except :
        print ("\033[95m"+'Unable to connect'+"\033[0m")
        sys.exit()

    print ("Connected to remote host. Your messages will be securely transmitted. ")
    sys.stdout.write("\033[34m"+'\n[local] #  '+ "\033[0m"); sys.stdout.flush()

    while 1:
        socket_list = [sys.stdin, s]
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

        for sock in read_sockets:
            if sock == s:

                data = sock.recv(4096)

                if not data :
                    print ("\033[95m"+"\nDisconnected from server"+"\033[0m")
                    sys.exit()
                else :
                    data = decrypt(key,data)
                    sys.stdout.write(data)
                    sys.stdout.write("\033[34m"+'\n[local] #  '+ "\033[0m"); sys.stdout.flush()

            else :

                msg = sys.stdin.readline()
                # msg = '[ '+ uname +': ] '+msg
                msg = encrypt(key,msg.encode("UTF-8"))
                s.send(msg.encode())
                sys.stdout.write("\033[34m"+'\n[local] #  '+ "\033[0m"); sys.stdout.flush()

if __name__ == "__main__":

    sys.exit(chat_client())
