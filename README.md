# shadowcrack
A simple CLI Tool for cracking Linux /etc/shadow hashed passwords.

## About
**shadowcrack** is a simple cli tool that attempts to crack hashed passwords stored under /etc/shadow file.

## Installation
```shell
git clone https://github.com/tommelo/shadowcrack
cd shadowcrack && sudo pip install -r requirements.txt
```

## Dependencies

* [colorama](https://pypi.python.org/pypi/colorama)
* [futures](https://pypi.python.org/pypi/futures) (Python2.7)
* [tqdm](https://pypi.python.org/pypi/tqdm)


## Usage
Short opt | Long opt | Default | Required | Description
--------- | -------- | ------- | -------- | -----------
-s        | --shadow     | None        | No      | The shadow file
-w        | --word-list  | None        | Yes     | The word list file
-v        | --verbose    | False       | No      | Enables the verbose mode
N/A       | --hashes-only| False       | No      | Shadow file contains only hashes
N/A       | --version    | None        | No      | Shows the current version

### The positional hash argument
```shell
python shadowcrack.py -v -w /usr/share/wordlists/rockyou.txt '$1$DUr3zqwq$mtnfrf.wtqmy6tyvzS/Xs1'
```
### -s, --shadow
The path of the shadow file:
```
root:$6$ab3HHKXt$AQsKnovqsftREfIwIG14AC.uAyAAn/gftQyTTXes89FRR8ayXXCWEbVyl7CeD9n8CAa6uq.CtRRWAA0AF89w.:17540:0:99999:7:::
```
### -w, --word-list
The word list file:
```
rawPassword1
rawPassword2
```

### -v, --verbose
Enables the verbose mode.

### --hashes-only
You may consider using this option if the shadow file contains a list of hashes only:

```
$1$DUr3zqwq$mtnfrf.wtqmy6tyvzS/Xs1
$6$ab3HHKXt$AQsKnovqsftREfIwIG14AC.uAyAAn/gftQyTTXes89FRR8ayXXCWEbVyl7CeD9n8CAa6uq.CtRRWAA0AF89w.
```

### --version
Shows the current version of the application.


### -h, --help
Shows the help usage.

## License
This is an open-source software licensed under the [MIT license](https://opensource.org/licenses/MIT).
