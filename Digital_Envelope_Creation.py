#!/usr/bin/env python
# coding: utf-8

# In[1]:


import random
import rsa
from pyDes import *


# In[2]:


def randomKey(): 
    randChar = ['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
    random_symmetric_key = ""
    random.seed()
    for i in range(8):
        while True:
            tmp = random.randint(0,len(randChar)-1)
            if randChar[tmp] not in random_symmetric_key:
                break
        random_symmetric_key += randChar[tmp]
    print("隨機對稱鑰：",random_symmetric_key)
    return random_symmetric_key
def RSAencrypt(rK,pK):
    encrypt_symmetric_key = rsa.encrypt(rK.encode(), public_key)
    print("密鑰：",encrypt_symmetric_key)
    return encrypt_symmetric_key
def DESencrypt(rK,msg): 
    iv = b'12345678' #偏轉向量
    k = des(rK, CBC, iv, pad = None, padmode = PAD_PKCS5)
    msg = msg.encode('utf-8')
    encrypt_msg = k.encrypt(msg)
    print("密文：",encrypt_msg)
    return encrypt_msg


# In[3]:


import socket
HOST = '127.0.0.1'
PORT = 8001

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #創建socket
s.connect((HOST, PORT))

while True:
    public_key = s.recv(1024) #接收訊息
    public_key = rsa.PublicKey.load_pkcs1(public_key)
    print("接收者傳來的公鑰：",public_key)
    msg = input("請輸入要發送的訊息：")
    random_symmetric_key = randomKey()
    encrypt_symmetric_key = RSAencrypt(random_symmetric_key,public_key)
    encrypt_msg = DESencrypt(random_symmetric_key,msg)
    envelope = encrypt_symmetric_key + b'encrypt_msg' + encrypt_msg
    print("數位信封：",envelope)
    s.send(envelope) #發送訊息
    input()
    break   
s.close()

