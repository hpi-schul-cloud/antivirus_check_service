#!/bin/env/python
import sys
import random
import string
import hashlib
import binascii
import argparse

# Utility methods for generating and comparing RabbitMQ user password hashes.
#
# Rabbit Password Hash Algorithm:
# 
# Generate a random 32 bit salt:
# 908D C60A

# Concatenate that with the UTF-8 representation of the password (in this case test12):
# 908D C60A 7465 7374 3132

# Take the SHA-256 hash (assuming the hashing function wasn't modified): 
# A5B9 24B3 096B 8897 D65A 3B5F 80FA 5DB62 A94 B831 22CD F4F8 FEAD 10D5 15D8 F391

# Concatenate the salt again:
# 908D C60A A5B9 24B3 096B 8897 D65A 3B5F 80FA 5DB62 A94 B831 22CD F4F8 FEAD 10D5 15D8 F391

# Convert to base64 encoding:
# kI3GCqW5JLMJa4iX1lo7X4D6XbYqlLgxIs30+P6tENUV2POR

# Use the base64-encoded value as the password_hash value in the request JSON.
# 
# Sources:
# https://www.rabbitmq.com/passwords.html#computing-password-hash


def generate_random_salt():
    chars = string.ascii_letters + string.digits
    # only 4 Bytes = 32 Bit
    return ''.join(random.choice(chars) for i in range(4)).encode('hex')

def encode_rabbit_password_hash(salt, password):
    salt_and_password = salt + password.encode('utf-8').encode('hex')
    salt_and_password = bytearray.fromhex(salt_and_password)
    salted_sha256 = hashlib.sha256(salt_and_password).hexdigest()
    password_hash = salt + salted_sha256
    password_hash = bytearray.fromhex(salt + salted_sha256)
    return binascii.b2a_base64(password_hash).strip()

def decode_rabbit_password_hash(password_hash):
    password_hash = binascii.a2b_base64(password_hash)
    decoded_hash = password_hash.encode('hex')
    return (decoded_hash[0:8], decoded_hash[8:])

def check_rabbit_password(test_password, password_hash):
    salt, _ = decode_rabbit_password_hash(password_hash)
    test_password_hash = encode_rabbit_password_hash(salt, test_password)
    return test_password_hash ==  password_hash


parser = argparse.ArgumentParser(description='Encrypt password')
parser.add_argument('--password', required=True)
args = parser.parse_args()

salt = generate_random_salt()
sha256hash = encode_rabbit_password_hash(salt, args.password)

print '== Your generated sha256 hash =='
print '%s (with salt: %s)' % (sha256hash, salt)
print
print '== Check: ', check_rabbit_password(args.password, sha256hash)