#!/usr/bin/python3
import os
import argparse
import dpapick3

from browser import firepwd
from browser import chromedec
from dpapi import dpclass

root_dir = ''

if __name__ == '__main__':
	# arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir","-d",dest='dir', help="directory with the root drive")
    parser.add_argument("--password", "-p",dest="password", help="user password")
    parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password")
    parser.set_defaults(nopass=False)
    args = parser.parse_args()
    
    if (args.dir is None):
        print("You need to specify directory with the root unit")
        exit()
    root_dir = args.dir
    # Get Users
    all_users = os.listdir(os.path.join(root_dir, 'Users'))
    # Remove default users
    for user in ['All Users', 'Default User', 'Default', 'Public', 'desktop.ini', '.DS_Store']:
        if user in all_users:
            all_users.remove(user)

    print("\n\nMozilla\n\n")

    # Mozilla
    base_firefox = "{root}Users/{user}/AppData/Roaming/Mozilla/Firefox/Profiles"

    for user in all_users:
        profile_ff = base_firefox.format(root=root_dir, user=user)
        if os.path.isdir(profile_ff):
            # Only directories
            for item in os.listdir(profile_ff):
                if os.path.isdir(os.path.join(profile_ff,item)):
                    print("Profile found at " , os.path.join(profile_ff, item))
                    print("#" * 2)
                    firepwd.call_external(["-d",os.path.join(profile_ff,item)])
                
    print("\n\nDPAPI\n\n")

    # DPAPI
    # system dpapi    u'{root}/Windows/System32/config/systemprofile/AppData/Local/Microsoft/Vault'
    if args.password is not None:
        base_appdata = "{root}Users/{user}/AppData/"
        sid = ""
        for user in all_users:
            decrypted = False
            profile_appdata = base_appdata.format(root=root_dir, user=user)
            tem = os.path.join( profile_appdata , "Roaming" , "Microsoft", "Protect")
            if os.path.isdir(tem):
                for i in os.listdir(tem):
                    if i.startswith('S-'):
                        sid = i
                        # dpapi class - masterkey_dir, user_pass , sid, nopass, tba , config_hive)
                        print("Number of %s Masterkeys: %i " % (user ,len(os.listdir(os.path.join(tem, sid)))-1) )
                        user_dpapi =  dpclass.Dpapi_main( os.path.join(tem, sid), args.password, sid  ) 
                        print("Masterkeys decripted : " , user_dpapi.number_mk_dec )
                        # If some mks are decrypted
                        if user_dpapi.number_mk_dec > 0:
                            decrypted = True
                        # start dpapi class
            # Chrome starts here if any mk is working
            if decrypted:
                print("\n\nChrome\n\n")

                chrome_base = "{root}/Users/{user}/AppData/Local/Google/Chrome/User Data"
                chrome_profile = chrome_base.format(root=root_dir, user=user)
                # use the dpapi class to get de decrypton key
                dec_key = user_dpapi.chrome_blob(os.path.join(chrome_profile, "Local State"))
                # call the function that read the encrypted passwords and dum them)
                chromedec.dump_passwords(chrome_profile, dec_key)

            # other DPAPI implementations like VAULT should come here


