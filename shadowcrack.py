#!/usr/bin/env python

import sys, os.path
from crypt import *
from hmac import compare_digest as compare_hash
from getopt import *

#######################################################
#
# shadowcrack.py
#
# This cli tool tries to crack the Linux users hashed 
# passwords that is stored in /etc/shadow file
#
# [mr.church]
#
#######################################################

app_name     = "shadowcrack"
app_version  = "1.0.0"
banner       = """
  _____ _               _                  _____                _
 / ____| |             | |                / ____|              | |
| (___ | |__   __ _  __| | _____      __ | |     _ __ __ _  ___| | __
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / | |    | '__/ _` |/ __| |/ /
 ____) | | | | (_| | (_| | (_) \ V  V /  | |____| | | (_| | (__|   <
|_____/|_| |_|\__,_|\__,_|\___/ \_/\_/    \_____|_|  \__,_|\___|_|\_/

[mr.church]                                       {} v{}

"""

help_usage = """

usage: shadowcrack [options]

options:

-h --help     Shows the help usage
-v --version  Shows the current version
-p --password The hash password to be cracked
              The hash passwod must be specified with $'yourhashhere'
-l --list     The password list file (pwd.txt if none is provided)

Eg.:

    python shadowcrack.py -p $'$6$VLr2CiTR$mltwV7.zGeocAoyqUIjHZKXMn8gzRqoszAu/DAK2.pOrw1rJTdI/XQRzHgIgz4id.kuRSEu6XbgGDvJX8Jfm/0'

"""

options = "hvp:l:"
long_options = ["help", "version", "password=", "list="]

hash_methods = {
    '1' : 'MD5',
    '2a': 'Blowfish',
    '5' : 'SHA-256',
    '6' : 'SHA-512'
}

wordlist = "pwd.txt"
hashpwd  = None

#
# prints the help usage
#
# arg -h or --help
#
def usage():
    print(help_usage);

#
# prints the current version
#
# arg -v or --version
#
def version():
    print("{} v{}".format(app_name, app_version))

#
# parses the given arguments
#
# current supported args:
# -h --help
# -v --version
# -p --password
# -l --list
#
def parseargs(argv):
    try:
        opts, args = getopt(argv, options, long_options)
        if len(opts) == 0:
            print("[!] No arguments given")
            print("[!] Use --help for help usage")
            sys.exit(1)

        for opt, arg in opts:
            if opt in ("-v", "--version"):
                version()
                sys.exit(0)

            elif opt in ("-h", "--help"):
                usage()
                sys.exit(0)

            elif opt in ("-p", "--password"):
                global hashpwd
                hashpwd = arg

            elif opt in ("-l", "--list"):
                global wordlist
                wordlist = arg

        if hashpwd is None or not hashpwd:
           print("[!] No hash password given")
           print("[!] Use --help for help usage")
           sys.exit(1)

        if not os.path.exists(wordlist):
           print("[!] File {} not found".format(wordlist))
           print("[!] Use --help for help usage")
           sys.exit(1)

    except GetoptError as error:
        print("")
        print(error)
        usage()
        sys.exit(1)

#
# the main function
#
# tries to identify the hash algorithm, the hash salt
# and compare the given hashed password to a list of raw passwords.
# 
def main(args):
    parseargs(args)
    print(banner.format(app_name, app_version))

    lindex      = hashpwd.rfind('$')
    hashmethod  = hashpwd[1:2];
    salt        = hashpwd[3:lindex];

    if not hashmethod in hash_methods:
       print("[!] Unable to detect the hash method")
       sys.exit(1)

    method    = hash_methods[hashmethod]
    fsalt     = "${}${}$".format(hashmethod, salt)
    ispwdcrkd = False

    print("[+] Hash method: {} detected".format(method))
    print("[+] Hash salt:   {} detected \n".format(salt))
    print("[+] Trying to crack the hashed password")
    print("[+] Be patient...")

    f = open(wordlist)
    pwds = f.read().splitlines()
    f.close()

    for raw in pwds:
        crypted = crypt(raw, fsalt)
        if (compare_hash(crypted, hashpwd)):
           ispwdcrkd = True
           print("[+] Password cracked: {} \n".format(raw))
           break

    if not ispwdcrkd:
       print("[!] Unable to crack the hashed password \n")

    sys.exit(0)

#
# runs the application
#
if __name__ == "__main__":
    main(sys.argv[1:])
