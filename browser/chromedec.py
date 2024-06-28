#!/usr/bin/python3

import os
import json
import base64
import sqlite3
from Cryptodome.Cipher import AES
import argparse
import sys

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
        return decrypted_pass
    except Exception as e:
        # print(str(e))
        return "Credentials extraction error maybe enc_key is wrong or Chrome version < 80"

def dump_passwords( directory, enc_key):
    # get Multi user profile
    profile_list =[]
    dir_list = os.listdir(directory)
    for dirname in dir_list:
        if dirname.startswith('Profile'):
            profile_list.append(dirname)
    # Add default profile
    profile_list.append('Default')
    for profile in profile_list:
        print("### ### ### ### ### Profile %s ###### ######## ######### ####### " % profile)
        login_db = os.path.join( directory , profile ,'Login Data')
        conn = sqlite3.connect(login_db)
        cursor = conn.cursor()

        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password(encrypted_password, enc_key)
            print("*" * 50)
            print("URL: " + url + "\nUser Name: " + username + "\nPassword: " + decrypted_password + "\n" )

        cursor.close()
        conn.close()
    

if __name__ == '__main__':
    
    #init external class to decrypt enc_key
    #ret = chrome_dpapi.Dpapi_decrypt(args.dir,args.masterkey,args.password,args.sid, args.nopass, args.tba, args.config_reg)
    # ret.main()
    # Get key
    # enc_key = ret.return_key()
    # if (enc_key == ''):
    #    print("Error getting encription key")
    #    sys.exit()
    pass
    

