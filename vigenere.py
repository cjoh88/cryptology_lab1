#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys, getopt
import re
import io

ENCRYPT = 0
DECRYPT = 1
BREAK   = 2
TRIM    = 3

#ERROR_CODES
INVALID_ARGS    = 1
KEY_TO_LONG     = 2
INVALID_CHAR    = 3
NO_INPUT_FILE   = 4

ORD = [u"a", u"b", u"c", u"d", u"e", u"f", u"g", u"h", u"i", u"j", u"k", u"l", u"m", u"n", u"o", u"p",
 u"q", u"r", u"s", u"t", u"u", u"v", u"w", u"x", u"y", u"z", u"å", u"ä", u"ö", u" ", u",", u"."]

def is_valid(s):
    return re.match(u"^[a-z\u00E5\u00E4\u00F6 ,.]+$", s, flags=re.UNICODE)

def trim(input_file, output_file):
    i = io.open(input_file, "r", encoding="utf8")
    string = i.read()
    i.close
    string = string.lower()
    length = len(string)
    new_string = re.sub(u"[^a-z\u00E5\u00E4\u00F6 ,.]+", " ", string, flags=re.UNICODE)
    new_length = len(new_string)
    print("%s trimmed from %d characters to %d." % (input_file, length, new_length))
    o = io.open(output_file, "w", encoding="utf8")
    o.write(new_string)
    o.close()

def v_ord(c):
    for i, x in enumerate(ORD):
        if c == x:
            return i
    return -1

def v_chr(i):
    return ORD[i]

def error(s, error_code):
    print("Error: " + s)
    sys.exit(error_code)

def help():
    print("%s -i INPUTFILE -o OUTPUTFILE -k KEY [-e|-d|-b|-t]" % sys.argv[0])

def encrypt(input_file, output_file, key):
    f = io.open(input_file, "r", encoding="utf8")
    plaintext = f.read()
    f.close()
    if not is_valid(plaintext):
        error("File contains invalid characters. Trim file before encryption", INVALID_CHAR)
    key_length = len(key)
    alphabet_length = len(ORD)
    ciphertext = ""
    for i, c in enumerate(plaintext):
        key_index = i % key_length
        plaintext_value = v_ord(c)
        key_value = v_ord(key[key_index])
        cipher_value = (plaintext_value + key_value) % alphabet_length
        ciphertext += v_chr(cipher_value)
    f = io.open(output_file, "w", encoding="utf8")
    f.write(ciphertext)
    f.close()
    print(input_file + " encrypted and stored as " + output_file)

def decrypt(input_file, output_file, key):
    f = io.open(input_file, "r", encoding="utf8")
    ciphertext = f.read()
    f.close()
    key_length = len(key)
    plaintext = ""
    alphabet_length = len(ORD)
    for i, c in enumerate(ciphertext):
        key_index = i % key_length
        cipher_value = v_ord(c)
        key_value = v_ord(key[key_index])
        plain_value = (cipher_value + alphabet_length - key_value) % alphabet_length
        plaintext += v_chr(plain_value)
    f = io.open(output_file, "w", encoding="utf8")
    f.write(plaintext)
    f.close()
    print(input_file + " decrypted and stored as " + output_file)

def crack():
    pass

def main(argv):
    input_file = ""
    output_file = "output.txt"
    key = "key"
    function = ENCRYPT
    try:
        opts, args = getopt.getopt(argv, "hi:o:k:edbt")
    except getopt.GetoptError:
        error("Invalid arguments", INVALID_ARGS)
    for opt, arg in opts:
        if opt == "-h":
            help()
            sys.exit(0)
        elif opt in ("-i", "--ifile"):
            input_file = arg
        elif opt in ("-o", "--ofile"):
            output_file = arg
        elif opt in ("-k", "--key"):
            key = arg
            if len(key.decode("utf8")) > 16:
                error("Key is to long", KEY_TO_LONG)
            if not is_valid(key):
                error("Key contains invalid characters", INVALID_CHAR)
        elif opt in ("-e", "--encrypt"):
            function = ENCRYPT
        elif opt in ("-d", "--decrypt"):
            function = DECRYPT
        elif opt in ("-b", "--break"):
            function = BREAK
        elif opt in ("-t", "--trim"):
            function = TRIM
    if len(input_file) <= 0:
        error("No input file specified", NO_INPUT_FILE)
    if function == ENCRYPT:
        encrypt(input_file, output_file, key)
    elif function == DECRYPT:
        decrypt(input_file, output_file, key)
    elif function == BREAK:
        pass
    elif function == TRIM:
        trim(input_file, output_file)


if __name__ == "__main__":
    main(sys.argv[1:])
