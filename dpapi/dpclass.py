#!/usr/bin/python3
#
# 

import sys
import os
import json
import base64
import re
import binascii
from dpapick3 import blob, masterkey, registry

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
class Dpapi_main(object):
    def __init__(self, m=None, u=None, s=None, n=False, t=False, c=None):
        self.masterkey_location = m
        self.mkp = None 
        self.sid_value = s
        self.user_password = u
        self.nopass = n
        self.tba = t
        # hive windows location (windows\system32\config)
        self.config = c
        self.entropy= None
        self.enc_key =''
        self.number_mk_dec = 0 
        #open dpapi blob

        bl = blob.DPAPIBlob()
        
        file_list=[]
        if (self.masterkey_location):
            self.mkp = masterkey.MasterKeyPool()
            self.mkp.loadDirectory(self.masterkey_location)
        else:
            print("Needed masterkey(-m) directory with the location of " + bl.mkguid)
            sys.exit(2)
        if not (self.sid_value):
            print("No SSID ")
            sys.exit(2)
            '''
            try:
                self.sid_value = ( re.search('((S-1).*?)/', self.masterkey_location )[1])
                print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "SID " + self.sid_value )
            except:
                print("Need to specify SID")
                sys.exit(2)
            '''
        #Check if using TBA located key
        if self.tba:
            #TODO tba get key
            # read LSA secrets, find TBAL key
            reg = registry.Regedit()
            if self.config == None:
                sys.exit("Need to set config directory (\Windows\System32\config)")
            security = os.path.join(self.config,"SECURITY")
            system = os.path.join(self.config,"SYSTEM")
            if not(os.path.isfile(security) and os.path.isfile(system)):
                sys.exit("SYSTEM or SECURITY error opening")
            secrets = reg.get_lsa_secrets(security, system)
            for i in list(secrets.keys()):
                for k, v in list(secrets[i].items()):
                    if k in ('CurrVal', 'OldVal'):
                        data = v.hex()
                        if ("TBAL" in i):
                            ntlm = str(data)[32:64]
                            tbal_data = str(data)[96:136]
                            print ('NTLM: %s  DPAPI_key %s' % (ntlm, tbal_data))
                            try: print('User: %s' % binascii.unhexlify((data)[288:]).decode())
                            except:
                                pass
                            break
            if tbal_data == None:
                sys.exit("No TBAL found")
            # go for the decrypt
            key_p = binascii.unhexlify(tbal_data)
            self.mkp.try_credential_hash(self.sid_value,key_p)


        else:
            #Check if password or nopass
            if self.nopass:
                    self.user_password= ''
            elif self.user_password is None:
                print("Need user password (-p)")
                sys.exit(2)
            # go for the decrypt
            #Add chredhist
            #mkp.addCredhistFile(sid, os.path.join('Protect','CREDHIST'))
            print("Testing Masterkey password. This can take a while, more if the password is wrong")
            self.number_mk_dec = self.mkp.try_credential(self.sid_value, self.user_password)
    def chrome_blob(self, file_name):
        with open( file_name , "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        key = key[5:] 
        
        # load blob search mk
        bl = blob.DPAPIBlob(key)
        mks = self.mkp.getMasterKeys(bl.mkguid.encode()) 
        if len(mks) == 0:
            sys.exit('[-] Unable to find MK for blob %s' % bl.mkguid)
        else:
            print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "MasterKey file found" )

        for mk in mks:
            if self.tba:
                mk.decryptWithHash(self.sid_value,key_p)
            #else:
            #    mk.decryptWithPassword(self.sid_value,self.user_password)
            if mk.decrypted:
                print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "trying mks for chrome")
                bl.decrypt(mk.get_key(), entropy=self.entropy)
                if bl.decrypted:
                    # success
                    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Key Found")
                    return(bl.cleartext)
            else:
                # Just print the data
                print(bcolors.FAIL +" * * * * * * * * * *  "+ bcolors.ENDC )
                print(bcolors.FAIL +" * "+ bcolors.ENDC + "Error decrypting, Wrong Password?")
                print(bcolors.FAIL +" * * * * * * * * * *  "+ bcolors.ENDC )
                print(bl)


    def return_key(self):
        return(self.enc_key)

       
if __name__ == "__main__":
    #   obj = Dpapi_decrypt(args.dir, args.masterkey,args.password, args.sid, args.nopass,args.tba, args.config_reg)
    
    # obj.main()
    pass
