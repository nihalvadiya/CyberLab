import hashlib
import string
import itertools
import time

# Secret password
secret_password = "aB3"

# Hash it
secret_hash = hashlib.sha256(secret_password.encode()).hexdigest()

print("Secret hash:", secret_hash)
print("\nStarting brute force...\n")

characters = string.ascii_letters + string.digits
length = 3


attempts = 0
start_time = time.time()

for guess_tuple in itertools.product(characters, repeat=length):
    guess = ''.join(guess_tuple)
    attempts += 1

    guess_hash = hashlib.sha256(guess.encode()).hexdigest()

    if guess_hash == secret_hash:
        end_time = time.time()
        print("Password found:", guess)
        print("Attempts:", attempts)
        print("Time taken:", round(end_time - start_time, 4), "seconds")
        break
