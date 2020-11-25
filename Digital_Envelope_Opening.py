#!/usr/bin/env python
# coding: utf-8

# In[1]:


import rsa
from pyDes import *


# In[2]:


def RSAKey():
    public, private = rsa.newkeys(1024) # 生成公鑰和私鑰
    publicKey = public.save_pkcs1()
    privateKey = private.save_pkcs1()
    return publicKey, privateKey
def RSAdecrypt(esK,pK):
    private_key = rsa.PrivateKey.load_pkcs1(pK)
    random_symmetric_key = rsa.decrypt(esK, private_key)
    print("隨機對稱鑰：",random_symmetric_key.decode())
    return random_symmetric_key
def DESdecrypt(rK,msg):
    iv = b'12345678'
    k = des(rK, CBC, iv, pad = None, padmode = PAD_PKCS5)
    msg = k.decrypt(msg)
    print("訊息：",msg.decode('utf-8'))


# In[3]:


import socket
HOST = '127.0.0.1'
PORT = 8001

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)#創建socket
s.bind((HOST, PORT))#綁定
s.listen(5)#監聽

end = False
conn, addr = s.accept()
print('Connected by ', addr)

while True:
    public_key,private_key = RSAKey()  
    conn.send(public_key)
    envelope = conn.recv(1024)
    data = envelope.split(b'encrypt_msg')
    key = data[0]
    msg = data[1]
    print("密鑰：",key)
    print("密文：",msg)
    random_symmetric_key = RSAdecrypt(key,private_key)
    DESdecrypt(random_symmetric_key,msg)
    print("End.")
    input()
    break
s.close()

