# MIT License
#
# Copyright (c) 2017 Tom Melo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE

#!/usr/bin/env python
# -*- coding: utf-8; mode: python; py-indent-offset: 4; indent-tabs-mode: nil -*-
# vim: fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4
# pylint: disable=C0103,C0301,W1202,W0212

"""
Shadowcrack is a cli tool that attempts to crack
hashed passwords stored in /etc/shadow file.
"""

import argparse
import sys
import os
import logging
from crypt import *
from hmac import compare_digest as compare_hash
from concurrent.futures import ThreadPoolExecutor
from collections import namedtuple
from colorama import Fore
from colorama import Style
from colorama import init
from functools import partial
from mmap import mmap
from tqdm import tqdm
from helpformatter import HelpFormatter

VERSION = "v2.0.0"
BANNER = r"""
  _____ _               _                  _____                _
 / ____| |             | |                / ____|              | |
| (___ | |__   __ _  __| | _____      __ | |     _ __ __ _  ___| | __
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / | |    | '__/ _` |/ __| |/ /
 ____) | | | | (_| | (_| | (_) \ V  V /  | |____| | | (_| | (__|   <
|_____/|_| |_|\__,_|\__,_|\___/ \_/\_/    \_____|_|  \__,_|\___|_|\_/

[mr.church]                                           {}
"""

progress_bar = None
cracked_passwords = []

UNKNOWN_ACCOUNT = "<UNKNOWN>:{}:00000:0:00000:0:::"
HASH_ALGORITHMS = {
    '1' : 'MD5',
    '2a': 'Blowfish',
    '5' : 'SHA-256',
    '6' : 'SHA-512'
}

UnixAccount = namedtuple(
    "UnixAccount",
    [
        "algorithm",
        "hash_salt",
        "hashed_password",
        "raw_password",
        "username"
    ])

UnixAccount.__new__ = partial(
    UnixAccount.__new__,
    algorithm=None,
    hash_salt=None,
    hashed_password=None,
    raw_password=None,
    username=None)

parser = argparse.ArgumentParser(
    prog="shadowcrack",
    usage="shadowcrack <options> <hash>",
    formatter_class=HelpFormatter)
parser.add_argument("hash", nargs="?", help="The hashed password")
parser.add_argument("-s", "--shadow", metavar="", required=False, help="The /etc/shadow file")
parser.add_argument("-w", "--word-list", metavar="", required=True, help="The word list file")
parser.add_argument("-v", "--verbose", action="store_true", help="Enables the verbose mode")
parser.add_argument("--hashes-only", action="store_true", help="Shadow file contains only hashes")
parser.add_argument("--version", action="version", version=VERSION)

# log format:
# {color}{icon} {reset/color}{message}
LOG_FORMAT = "{}\033[1m{}\033[0m {}{}"
SUCCESS_LOG_FORMAT = "{0}\033[1m{1}\033[0m {2}{3:14}{4}"
UNDERLINED_FORMAT = '\033[4m{}\033[0m'

logging.basicConfig(format="%(message)s")
log = logging.getLogger("shadowcrack")

# set colorama's auto reset to true
# this will avoid mixing colors when
# displaying messages on the terminal
init(autoreset=True)

def file_lines(path):
    """
    Counts the number of lines of the given file.

    Parameters
    -------
    path: str
        The path of the text file

    Returns
    -------
    int
        The number of lines of the given file
    """

    with open(path, 'r+') as dict_file:
        buf = mmap(dict_file.fileno(), 0)
        lines = 0
        readline = buf.readline
        while readline():
            lines += 1

    return lines

def filter_shadow_file(path, is_hashes_only):
    """
    Counts the number of lines of the given file.

    Parameters
    -------
    path: str
        The path of the text file

    Returns
    -------
    int
        The number of lines of the given file
    """

    accounts = []

    try:
        with open(path, 'r') as shadow:
            for account in shadow:
                account = account.strip()
                if is_hashes_only:
                    accounts.append(UNKNOWN_ACCOUNT.format(account))
                else:                
                    auth = account.split(':')
                    if auth[1] != '*' and auth[1] != '!':
                        accounts.append(account)
    except IndexError:
        log.error(LOG_FORMAT.format(Fore.RED, "[!]", Fore.RESET, 'Unable to filter the shadow file'))
        log.error(LOG_FORMAT.format(Fore.RED, "[!]", Fore.RESET, "Use the -h option for help usage"))

    return accounts

def crack_password(account, word_list, status_bar, password_count):
    """ Cracks the shadowed password """

    shadowed = account.split(":")
    username = shadowed[0]
    hashed_pwd = shadowed[1]
    lindex = hashed_pwd.rfind('$')
    hash_algorithm = hashed_pwd[1:2]
    salt = hashed_pwd[3:lindex]

    algorithm = HASH_ALGORITHMS[hash_algorithm]
    salt_format = "${}${}$".format(hash_algorithm, salt)

    with open(word_list, 'r') as raw_passwords:
        for raw_password in raw_passwords:
            raw_password = raw_password.strip()

            crypted = crypt(raw_password, salt_format)
            if (compare_hash(crypted, shadowed[1])):
                ua = UnixAccount(
                    username=username,
                    algorithm=algorithm,
                    hash_salt=salt,
                    hashed_password=shadowed[1],
                    raw_password=raw_password)

                cracked_passwords.append(ua)
                status_bar.update(password_count)
                break

            password_count -= 1
            status_bar.update(1)

def flush_outuput():
    """Flushes the result to the output"""

    if len(cracked_passwords) == 0:
        progress_bar.write(LOG_FORMAT.format(Fore.YELLOW, "[!]", Fore.RESET, "No password could be cracked"))
    else:
        progress_bar.write("[*]")
        progress_bar.write("[*] " + UNDERLINED_FORMAT.format("CRACKED PASSWORDS"))
        for account in cracked_passwords:
            raw = "{}\033[1m{}\033[0m{}".format(Fore.GREEN, account.raw_password, Fore.RESET)
            progress_bar.write("[*]")
            progress_bar.write(SUCCESS_LOG_FORMAT.format(Fore.GREEN, "[+]", Fore.RESET, "Username:", account.username))
            progress_bar.write(SUCCESS_LOG_FORMAT.format(Fore.GREEN, "[+]", Fore.RESET, "Hash:", account.hashed_password))
            progress_bar.write(SUCCESS_LOG_FORMAT.format(Fore.GREEN, "[+]", Fore.RESET, "Salt:", account.hash_salt))
            progress_bar.write(SUCCESS_LOG_FORMAT.format(Fore.GREEN, "[+]", Fore.RESET, "Algorithm:", account.algorithm))
            progress_bar.write(SUCCESS_LOG_FORMAT.format(Fore.GREEN, "[+]", Fore.RESET, "Raw Password:", raw))

    progress_bar.write("")

def main(args):
    """Executes the shadow crack"""

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if not os.path.isfile(args.word_list):
        error_message = "Word list file {} not found".format(args.word_list)
        log.error(LOG_FORMAT.format(Fore.RED, "[!]", Fore.RESET, error_message))
        log.error(LOG_FORMAT.format(Fore.RED, "[!]", Fore.RESET, "Use the -h option for help usage"))
        sys.exit(1)

    if args.shadow and not os.path.isfile(args.shadow):
        error_message = "Shadow file {} not found".format(args.shadow)
        log.error(LOG_FORMAT.format(Fore.RED, "[!]", Fore.RESET, error_message))
        log.error(LOG_FORMAT.format(Fore.RED, "[!]", Fore.RESET, "Use the -h option for help usage"))
        sys.exit(1)

    if not args.shadow and not args.hash:
        log.error(LOG_FORMAT.format(Fore.RED, "[!]", Fore.RESET, "No shadow file or hashed password given"))
        log.error(LOG_FORMAT.format(Fore.RED, "[!]", Fore.RESET, "Use the -h option for help usage"))
        sys.exit(1)

    log.info(BANNER.format(VERSION))
    log.info(LOG_FORMAT.format(Fore.RESET, "[+]", "", "Loading word list file: " + os.path.abspath(args.word_list)))

    password_count = file_lines(args.word_list)
    log.info(LOG_FORMAT.format(Fore.RESET, "[+]", "", "Loaded {} raw password(s) from word list file".format(password_count)))

    accounts = []

    # filtering the shadow file
    # only accounts that have shadowed passwords
    # will be considered by the filter
    if args.shadow:
        log.info(LOG_FORMAT.format(Fore.RESET, "[+]", "", "Filtering shadow file (only shadowed passwords)"))
        accounts = accounts + filter_shadow_file(args.shadow, args.hashes_only)

    if args.hash:
        accounts.append(UNKNOWN_ACCOUNT.format(args.hash))

    if len(accounts) < 1:
        log.info(LOG_FORMAT.format(Fore.YELLOW, "[!]", Fore.RESET, "No passwords to be cracked"))
        log.info("")
        sys.exit(0)

    workers = len(accounts)
    passwords_to_crack = len(accounts)
    pool = ThreadPoolExecutor(max_workers=workers)

    log.info(LOG_FORMAT.format(Fore.RESET, "[+]", "", "Starting {} thread(s) to crack {} password(s)".format(workers, passwords_to_crack)))
    log.info(LOG_FORMAT.format(Fore.RESET, "[+]", "", "This may take a while, be patient..."))

    global progress_bar
    total_progress_bar = len(accounts) * password_count    
    progress_bar = tqdm(total=total_progress_bar)
    for account in accounts:
        pool.submit(crack_password, account, args.word_list, progress_bar, password_count)

    pool.shutdown(wait=True)
    flush_outuput()
    progress_bar.close()
    sys.exit()

if __name__ == "__main__":
    try:
        args = parser.parse_args()
        main(args)
    except KeyboardInterrupt:
        progress_bar.write(LOG_FORMAT.format(Fore.YELLOW, "[+]", Fore.RESET, "User requested to stop..."))
        flush_outuput()
        os._exit(0)
