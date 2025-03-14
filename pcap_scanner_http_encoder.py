#!/usr/bin/env python3
import sys
import pyshark
import base64
import string
from urllib.parse import unquote


###### Argument Parsing ######
if len(sys.argv) != 3:
  print("[-] Require exactly 2 Parameters.")
  exit()

log_filename = sys.argv[1]
algorithm = sys.argv[2]
###########################


def decryptCaesar(cipher, key):
  alphabet = string.ascii_lowercase
  alphabet += string.ascii_uppercase
  decrypted_message = ""

  for c in cipher:
    if c in alphabet:
      position = alphabet.find(c)
      new_position = (position - key) % 26
      new_character = alphabet[new_position]
      decrypted_message += new_character
    else:
      decrypted_message += c

  return decrypted_message


def main():
  print("[+] Starting HTTP Message Filter")
  cap = pyshark.FileCapture(log_filename, display_filter='http && ip.dst == 146.64.213.83')

  for packet in cap:
    message = packet.http.get_field_value('request.uri.query.parameter').split("=")[1]

    if algorithm == "plain":
      print(message)
    elif algorithm == "base64":
      print(base64.b64decode(unquote(message)).decode('utf-8'))
    elif algorithm == "base32":
      print(base64.b32decode(unquote(message)).decode('utf-8'))
    elif algorithm == "base16":
      print(base64.b16decode(message).decode('utf-8'))
    elif algorithm == "rot7":
      print(decryptCaesar(message,7))
    elif algorithm == "rot_custom":
      offset = int(packet.http.get_field_value('request.uri.query').split("=")[-1])
      message = packet.http.get_field_value('request.uri.query').split("=")[-2].split("&")[0]
      print(decryptCaesar(message,offset))
    elif algorithm == "trith":
      i = 0
      exlude = "+" + string.digits
      plaintext = ""
      for c in message:
        if c not in exlude:
          plaintext += decryptCaesar(c,i)
          i += 1
        else:
          plaintext += c
      print(plaintext)

if __name__ == "__main__":
  main()
