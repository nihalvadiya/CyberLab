import bcrypt

# Step 1: Ask user to create password
user_password = input("Create a password: ")

# Convert to bytes (bcrypt requires bytes format)
password_bytes = user_password.encode()

# Step 2: Generate salt automatically
salt = bcrypt.gensalt()

# Step 3: Hash the password
hashed_password = bcrypt.hashpw(password_bytes, salt)

print("\nStored hash in database:")
print(hashed_password)

# Step 4: Simulate login
print("\n--- LOGIN ---")
login_attempt = input("Enter your password to login: ").encode()

# Step 5: Check password
if bcrypt.checkpw(login_attempt, hashed_password):
    print("Login successful!")
else:
    print("Wrong password!")
