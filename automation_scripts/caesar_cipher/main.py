"""
CAESAR CIPHER — Encrypt / Decrypt Tool
Security Engineer Interview Practice Problem #4

=====================================================================
REFERENCE NOTES — ord/chr, ASCII, Modular Arithmetic, String Methods
=====================================================================

WHY THIS MATTERS FOR SE INTERVIEWS:
--------------------------------------
  - Google SE candidates report being asked to implement basic ciphers
  - Tests string manipulation, encoding knowledge, and clean code
  - Understanding encoding vs encryption is a common interview question:
      Encoding (base64): transforms format, NOT secret, easily reversible
      Encryption (AES):  transforms with a KEY, secret, only reversible with key
      Hashing (SHA256):  one-way, NOT reversible, used for verification
  - Caesar cipher is technically encoding (no real secret), but teaches
    the mechanics used in real encryption


ord() AND chr() — CHARACTER ↔ NUMBER CONVERSION:
---------------------------------------------------
  ord('A')  → 65     converts character to ASCII number
  chr(65)   → 'A'    converts ASCII number back to character

  ASCII layout for letters:
    A=65  B=66  C=67  ... X=88  Y=89  Z=90
    a=97  b=98  c=99  ... x=120 y=121 z=122

  After Z (90), ASCII has [=91 \=92 ]=93 — NOT letters!
  This is why you can't just do chr(ord(char) + shift).


WHY WE CAN'T JUST ADD THE SHIFT DIRECTLY:
--------------------------------------------
  chr(ord('A') + 3) = chr(68)  = 'D'   ← works
  chr(ord('H') + 3) = chr(75)  = 'K'   ← works
  chr(ord('Y') + 3) = chr(92)  = '\'   ← BROKEN! Expected 'B'
  chr(ord('Z') + 3) = chr(93)  = ']'   ← BROKEN! Expected 'C'

  The problem: after Z (90), ASCII characters are NOT letters.
  We need % 26 to wrap around, but modulo only works on 0-25 range.

  The fix: normalize to 0-25 first, THEN shift and modulo, THEN restore.

  ASCII world:    65 66 67 ... 89 90 [91 92 93]  ← junk after Z
                  A  B  C  ... Y  Z  [  \  ]

  Position world:  0  1  2 ... 24 25 [wraps → 0  1  2]  ← modulo works
                   A  B  C ... Y  Z          A  B  C


THE FORMULA STEP BY STEP:
---------------------------
  chr((ord(char) - base + shift) % 26 + base)

  Example: char='Y', shift=3, base=ord('A')=65

  Step 1: ord('Y') - base     = 89 - 65 = 24    (normalize to 0-25)
  Step 2: 24 + shift           = 24 + 3  = 27    (apply shift)
  Step 3: 27 % 26              = 1                (wrap around)
  Step 4: 1 + base             = 1 + 65  = 66    (restore to ASCII)
  Step 5: chr(66)              = 'B'              (convert back to char)

  Y shifted by 3 wraps around to B. Correct!


MODULO (%) — THE WRAP-AROUND OPERATOR:
----------------------------------------
  % gives the remainder after division.

  10 % 26 = 10    (10 / 26 = 0 remainder 10)
  25 % 26 = 25    (25 / 26 = 0 remainder 25)
  26 % 26 = 0     (26 / 26 = 1 remainder 0)  ← wraps!
  27 % 26 = 1     (27 / 26 = 1 remainder 1)  ← wraps!
  52 % 26 = 0     (52 / 26 = 2 remainder 0)  ← double wrap

  For Caesar cipher: keeps position in 0-25 range no matter how big the shift.
  shift % 26 normalizes the shift itself (shift of 29 = shift of 3).


USEFUL STRING METHODS:
------------------------
  char.isalpha()   → True if character is a letter (a-z, A-Z)
  char.islower()   → True if lowercase
  char.isupper()   → True if uppercase
  char.isdigit()   → True if a digit (0-9)
  char.isalnum()   → True if letter or digit


DECRYPT = ENCRYPT WITH NEGATIVE SHIFT:
-----------------------------------------
  Shifting forward by 3 to encrypt → shift backward by 3 to decrypt.
  encrypt(text, -shift) does the decryption.
  No need for separate decrypt logic — elegant and less code to debug.


ONE-LINE RECALLS:
------------------
  Formula:    "Normalize to 0-25, shift, modulo 26 to wrap, add base back"
  Why not direct: "ASCII has junk after Z — modulo only works in 0-25 range"
  ord/chr:    "ord() char→number, chr() number→char — A=65, a=97"
  Modulo:     "% 26 wraps any number back into 0-25 range"
  Decrypt:    "Decrypt is just encrypt with negative shift"

=====================================================================
"""

import argparse


def encrypt(text, shift):
    """Encrypt text using Caesar cipher with given shift."""
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                base = ord('a')
            else:
                base = ord('A')
            result += chr((ord(char) - base + shift_amount) % 26 + base)
        else:
            result += char
    return result


def decrypt(text, shift):
    """Decrypt Caesar cipher — just encrypt with negative shift."""
    return encrypt(text, -shift)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Caesar Cipher Encryptor/Decryptor")
    parser.add_argument("text", help="Text to encrypt/decrypt")
    parser.add_argument("shift", type=int, help="Shift amount")
    args = parser.parse_args()

    ciphertext = encrypt(args.text, args.shift)
    print(f"Encrypted: {ciphertext}")

    decrypted_text = decrypt(ciphertext, args.shift)
    print(f"Decrypted: {decrypted_text}")