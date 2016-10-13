# shadowcrack
CLI Tool for cracking Linux /etc/shadow hashed passwords

```
  _____ _               _                  _____                _
 / ____| |             | |                / ____|              | |
| (___ | |__   __ _  __| | _____      __ | |     _ __ __ _  ___| | __
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / | |    | '__/ _` |/ __| |/ /
 ____) | | | | (_| | (_| | (_) \ V  V /  | |____| | | (_| | (__|   <
|_____/|_| |_|\__,_|\__,_|\___/ \_/\_/    \_____|_|  \__,_|\___|_|\_/

```

###Options
```
-h --help     Shows the help usage
-v --version  Shows the current version
-p --password The hash password to be cracked
              The hash passwod must be specified with $'yourhashhere'
-l --list     The password list file (pwd.txt if none is provided)
```

###Usage
```
python shadowcrack.py -p $'$6$VLr2CiTR$mltwV7.zGeocAoyqUIjHZKXMn8gzRqoszAu/DAK2.pOrw1rJTdI/XQRzHgIgz4id.kuRSEu6XbgGDvJX8Jfm/0'
```

###Example
```
python shadowcrack.py -p $'$6$VLr2CiTR$mltwV7.zGeocAoyqUIjHZKXMn8gzRqoszAu/DAK2.pOrw1rJTdI/XQRzHgIgz4id.kuRSEu6XbgGDvJX8Jfm/0'

  _____ _               _                  _____                _
 / ____| |             | |                / ____|              | |
| (___ | |__   __ _  __| | _____      __ | |     _ __ __ _  ___| | __
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / | |    | '__/ _` |/ __| |/ /
 ____) | | | | (_| | (_| | (_) \ V  V /  | |____| | | (_| | (__|   <
|_____/|_| |_|\__,_|\__,_|\___/ \_/\_/    \_____|_|  \__,_|\___|_|\_/

[mr.church]                                       shadowcrack v1.0.0


[+] Hash method: SHA-512 detected
[+] Hash salt:   VLr2CiTR detected 

[+] Trying to crack the hashed password
[+] Be patient...
[+] Password cracked: a1c2 

```

###Todo

* Parse shadow file, enumerate users and passwords cracked
