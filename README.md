# mRemoteNGpasswordsStealer

## Description

This module steals mRemoteNG passwords.

## Requirements

This package require:
 - python3
 - python3 Standard Library
 - PythonToolsKit
 - PyCryptodome

## Installation

```bash
git clone https://github.com/mauricelambert/mRemoteNGpasswordsStealer.git
cd mRemoteNGpasswordsStealer
pip install .
```

## Usages

## Command lines

```bash
# Python executable
python3 mRemoteNGpasswordsStealer.pyz -h
# or
chmod u+x mRemoteNGpasswordsStealer.pyz
./mRemoteNGpasswordsStealer.pyz --help

# Python module
python3 -m mRemoteNGpasswordsStealer

# Entry point (console)
RemotePasswordsStealer -c -p mR3m -f C:\Users\Marine\AppData\Roaming\mRemoteNG\confCons.xml.20160622-0935582042.backup
```

### Python script

```python
from mRemoteNGpasswordsStealer import Stealer
stealer = Stealer()
stealer = Stealer("mRemoteNG_passwords", "mR3m", r"C:\Users\Marine\AppData\Roaming\mRemoteNG\confCons.xml.20160622-*.backup", True)
for host, user, password in stealer.parse_all():
    print(host, user, password)

stealer.success_coutner
stealer.errors_counter
```

## Help

```text
~# python mRemoteNGpasswordsStealer.py -h

usage: mRemoteNGpasswordsStealer.py [-h] [-p PASSWORD] [-f FILE]

This program steals mRemoteNG passwords.

optional arguments:
  -h, --help            show this help message and exit
  -p PASSWORD, --password PASSWORD
                        mRemoteNG master password.
  -f FILE, --file FILE  mRemoteNG configuration file.
  -c, --copy, --copy-config
                        Copy mRemoteNG configuration file.
  -e EXPORT, --export EXPORT, --export-file EXPORT
                        Export filename.
```

## Links

 - [Github Page](https://github.com/mauricelambert/mRemoteNGpasswordsStealer/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/mRemoteNGpasswordsStealer.html)
 - [Download as python executable](https://mauricelambert.github.io/info/python/security/mRemoteNGpasswordsStealer.pyz)
 - [Windows Executables](https://github.com/mauricelambert/mRemoteNGpasswordsStealer/releases)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
