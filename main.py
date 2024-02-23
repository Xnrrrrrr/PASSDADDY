import secrets
import sqlite3
import string
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
from prettytable import prettytable, PrettyTable
from datetime import datetime, timedelta
import sys
import re
import getpass  # Import the getpass module for secure password input



MAX_FAILED_ATTEMPTS = 3  # Maximum allowed failed attempts
from sqlite3 import Cursor
DATABASE_FILE = "passwords.db"
ENCRYPTION_KEY_FILE = "encryption_key.bin"
encoded_password = None  # Declare encoded_password at the global scope
encryption_key = None

def create_tables(connection):
    cursor = connection.cursor()

    # Create accounts table
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts
                      (id INTEGER PRIMARY KEY, username TEXT, password TEXT, medium TEXT)''')

    # Create master_accounts table if not exists
    cursor.execute('''CREATE TABLE IF NOT EXISTS master_accounts
                      (id INTEGER PRIMARY KEY, username TEXT, password TEXT, remaining_attempts INTEGER DEFAULT 3, last_failed_attempt TIMESTAMP)''')

    connection.commit()


def calculate_password_strength(password):
    # Minimum length requirement
    length_score = max(0, min(len(password) // 4, 3))

    # Check for uppercase letters
    uppercase_score = int(bool(re.search(r'[A-Z]', password)))

    # Check for lowercase letters
    lowercase_score = int(bool(re.search(r'[a-z]', password)))

    # Check for digits
    digit_score = int(bool(re.search(r'\d', password)))

    # Check for special characters
    special_char_score = int(bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)))

    # Combine scores into a total strength score (out of 10)
    total_score = length_score + uppercase_score + lowercase_score + digit_score + special_char_score

    return total_score
# fix 4 pois
def display_password_strength(password_strength):
    print(f"Password Strength: {password_strength}/10")

def load_or_generate_encryption_key():
    global encryption_key

    try:
        with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
            encryption_key = key_file.read()
    except FileNotFoundError:
        # If the key file doesn't exist, generate a new key
        encryption_key = generate_strong_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
            key_file.write(encryption_key)


def print_table(data, cursor):
    if not data:
        print("No records found.")
        return

    table = PrettyTable()

    # Get column names using the cursor description
    columns = [description[0] for description in cursor.description]

    table.field_names = columns
    table.add_rows(data)
    print(table)



def print_database_contents(connection):
    cursor = connection.cursor()

    # Print accounts table
    print("\nAccounts Table:")
    cursor.execute("SELECT * FROM accounts")
    accounts = cursor.fetchall()
    print_table(accounts, cursor)

    # Print master_accounts table
    print("\nMaster Accounts Table:")
    cursor.execute("SELECT * FROM master_accounts")
    master_accounts = cursor.fetchall()
    print_table(master_accounts, cursor)  # <-- Corrected line



def create_master_account(connection, encryption_key):
    cursor = connection.cursor()

    # Check if there is already a master account
    cursor.execute("SELECT COUNT(*) FROM master_accounts")
    count = cursor.fetchone()[0]

    if count == 0:
        # Prompt for master account creation
        master_username = input("Enter the master account username: ")
        master_password = input("Enter the master account password: ")

        # Hash and encrypt master account password
        master_password_hash = hashlib.sha256(master_password.encode()).digest()
        master_password_encrypted = encrypt_password(master_password_hash, encryption_key)

        # Save master account information
        cursor.execute("INSERT INTO master_accounts (username, password) VALUES (?, ?)",
                       (master_username, master_password_encrypted))
        connection.commit()
        print("Master account created successfully.")
    else:
        print("Master account already exists.")

def generate_strong_key():
    # Generate a strong random key (replace this with a secure key management solution)
    return secrets.token_bytes(32)


def encrypt_password(password, key):
    # Ensure that the password is in bytes
    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    elif isinstance(password, bytes):
        password_bytes = password
    else:
        raise ValueError("Invalid password type. Must be str or bytes.")

    # Pad the password to meet block size requirements
    password_bytes = password_bytes.ljust(32)

    # Generate an IV (Initialization Vector)
    iv = b'\x00' * 16

    # Create a cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Encrypt the password
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password_bytes) + encryptor.finalize()

    # Encode the encrypted password for storage
    global encoded_password
    encoded_password = base64.b64encode(encrypted_password)

    return encoded_password




def authenticate_master_account(connection, encryption_key):
    cursor = connection.cursor()

    while True:
        print("\033[34m")  # Set text color to blue
        username = input("Enter master account username: ")

        # Check if the master account is locked
        if is_master_account_locked(connection, username):
            print(f"{username}'s account is locked. Please try again later.")
            return False  # Authentication failed

        password = input("Enter master account password: ")
        print("\033[0m")  # Reset text color to default

        password_hash = hashlib.sha256(password.encode()).digest()

        cursor.execute("PRAGMA table_info(master_accounts)")
        columns = [column[1] for column in cursor.fetchall()]

        if 'last_failed_attempt' not in columns:
            cursor.execute('''ALTER TABLE master_accounts
                              ADD COLUMN last_failed_attempt TIMESTAMP''')
            connection.commit()

        cursor.execute("SELECT password, remaining_attempts, last_failed_attempt FROM master_accounts WHERE username = ?", (username,))
        account_info = cursor.fetchone()

        if account_info:
            encrypted_password, remaining_attempts, last_failed_attempt_str = account_info

            if remaining_attempts > 0:
                decrypted_password_bytes = decrypt_and_decode_password(encrypted_password, encryption_key)

                print(f"Decrypted Password Bytes: {decrypted_password_bytes}")
                print(f"Entered Password Hash: {password_hash}")

                # Test against password_hash
                if password_hash == decrypted_password_bytes:
                    # Reset remaining attempts upon successful login
                    cursor.execute("UPDATE master_accounts SET remaining_attempts = 3, last_failed_attempt = NULL WHERE username = ?", (username,))
                    connection.commit()
                    print("Authentication successful.")
                    return True  # Authentication successful

            remaining_attempts -= 1

            # Update last_failed_attempt with the current timestamp
            last_failed_attempt = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            cursor.execute(
                "UPDATE master_accounts SET remaining_attempts = ?, last_failed_attempt = ? WHERE username = ?",
                (remaining_attempts, last_failed_attempt, username)
            )
            connection.commit()

            print(f"Remaining attempts: {remaining_attempts}")

            if remaining_attempts == 0:
                print("Too many failed attempts. Account locked.")
                return False  # Authentication failed

            # Check if the lockout period has passed (1 minute)
            if last_failed_attempt_str:
                last_failed_attempt = datetime.strptime(last_failed_attempt_str, "%Y-%m-%d %H:%M:%S.%f")
                elapsed_time = datetime.now() - last_failed_attempt
                if elapsed_time.total_seconds() < 60:
                    print("Account is locked. Please try again later.")
                    return False  # Authentication failed

            print("Incorrect password. Please try again.")

        else:
            print("Authentication failed. User not found.")
            return False  # Authentication failed







def is_master_account_locked(connection, master_username):
    cursor = connection.cursor()

    cursor.execute("SELECT remaining_attempts, last_failed_attempt FROM master_accounts WHERE username = ?", (master_username,))
    account_info = cursor.fetchone()

    if account_info:
        remaining_attempts, last_failed_attempt_str = account_info

        if remaining_attempts == 0 and last_failed_attempt_str:
            last_failed_attempt = datetime.strptime(last_failed_attempt_str, "%Y-%m-%d %H:%M:%S.%f")
            if datetime.now() - last_failed_attempt < timedelta(hours=1):
                return True

    return False




def decrypt_and_decode_password(encoded_password, key):
    # Decode the encoded password
    encrypted_password = base64.b64decode(encoded_password)

    # Generate an IV (Initialization Vector)
    iv = b'\x00' * 16

    # Create a cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Decrypt the password
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

    # Return the decrypted password as bytes
    return decrypted_password


def generate_password(length=12, uppercase=True, digits=True, special_characters=True):
    characters = string.ascii_lowercase
    if uppercase:
        characters += string.ascii_uppercase
    if digits:
        characters += string.digits
    if special_characters:
        characters += string.punctuation

    if length < 1:
        raise ValueError("Password length must be at least 1")

    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

def save_account(connection, username, password, medium, encryption_key):
    cursor = connection.cursor()

    # Hash and encrypt the password before saving
    hashed_and_encrypted_password = encrypt_password(password, encryption_key)

    # Save the hashed and encrypted password in the accounts table
    cursor.execute("INSERT INTO accounts (username, password, medium) VALUES (?, ?, ?)",
                   (username, hashed_and_encrypted_password, medium))
    connection.commit()

    return hashed_and_encrypted_password

def load_accounts(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM accounts")
    accounts = cursor.fetchall()
    return accounts

def view_accounts(connection):
    accounts = load_accounts(connection)

    if not accounts:
        print("No accounts found.")
    else:
        print("\nStored Accounts:")
        for account in accounts:
            print(f"  ID: {account[0]}, Username: {account[1]}, Password: {account[2]}, Medium: {account[3]}")

def generate_random_password():
    password = generate_password()
    print(f"\nGenerated Random Password: {password}")
    return password



def wipe_all_data(connection, encryption_key):
    confirmation = input("This action will permanently delete all data and the database file. Are you sure? (yes/no): ")
    if confirmation.lower() == 'yes':
        cursor = connection.cursor()

        # Delete all data from the accounts table
        cursor.execute("DELETE FROM accounts")

        # Delete all data from the master_accounts table
        cursor.execute("DELETE FROM master_accounts")

        connection.commit()
        print("All data wiped successfully.")

        # Close the database connection
        connection.close()

        # Delete the database file
        try:
            os.remove(DATABASE_FILE)
            print(f"Database file '{DATABASE_FILE}' deleted successfully.")
        except FileNotFoundError:
            print(f"Database file '{DATABASE_FILE}' not found.")
        except Exception as e:
            print(f"Error deleting database file: {e}")

    else:
        print("Wipe operation canceled.")

def change_master_password(connection, encryption_key):
    cursor = connection.cursor()

    # Get the current master account username
    cursor.execute("SELECT username FROM master_accounts LIMIT 1")
    current_username = cursor.fetchone()

    if not current_username:
        print("No master account found. Please create a master account first.")
        return

    print(f"\nChanging password for master account: {current_username[0]}")

    # Prompt for the current password
    current_password = getpass.getpass("Enter current master account password: ")

    # Authenticate the current password
    if not authenticate_master_account(connection, encryption_key, current_password):
        print("Authentication failed. Unable to change password.")
        return

    # Prompt for the new password
    new_password = getpass.getpass("Enter new master account password: ")
    confirm_new_password = getpass.getpass("Confirm new master account password: ")

    # Check if the new password and confirmation match
    if new_password != confirm_new_password:
        print("New password and confirmation do not match. Password change failed.")
        return

    # Hash and encrypt the new password
    new_password_hash = hashlib.sha256(new_password.encode()).digest()
    new_password_encrypted = encrypt_password(new_password_hash, encryption_key)

    # Update the master account password
    cursor.execute("UPDATE master_accounts SET password = ? WHERE username = ?", (new_password_encrypted, current_username[0]))
    connection.commit()

    print("Master account password changed successfully.")



def welcome_message():
    welcome_art = """
\033[91m
 _______     _       ______    ______   ______        _       ______   ______   ____  ____  
|_   __ \   / \    .' ____ \ .' ____ \ |_   _ `.     / \     |_   _ `.|_   _ `.|_  _||_  _| 
  | |__) | / _ \   | (___ \_|| (___ \_|  | | `. \   / _ \      | | `. \ | | `. \ \ \  / /   
  |  ___/ / ___ \   _.____`.  _.____`.   | |  | |  / ___ \     | |  | | | |  | |  \ \/ /    
 _| |_  _/ /   \ \_| \____) || \____) | _| |_.' /_/ /   \ \_  _| |_.' /_| |_.' /  _|  |_    
|_____||____| |____|\______.' \______.'|______.'|____| |____||______.'|______.'  |______|   

> Written by Xnrrrrrr
> v1.0

\033[0m
    """
    print(welcome_art)

def print_menu():
    border = "+" + "-"*30 + "+"
    menu = (
        "\033[91m                    ,---.           ,---.\n"
        "                    / /\"`\\.--\"\"\"--./,'\"\\ \\\n"
        "                    \\ \\    _       _    / /\n"
        "                     `./  / __   __ \\  \\,'\n"
        "                      /    /_O)_(_O\\    \\\n"
        "                      |  .-'  ___  `-.  |\n"
        "                   .--|       \\_/       |--.\n"
        "                 ,'    \\   \\   |   /   /    `.\n"
        "                /       `.  `--^--'  ,'       \\\n"
        "             .-\"\"\"\"\"\"-.    `--.___.--'     .-\"\"\"\"\"\"-.\n"
        ".-----------/         \\------------------/         \\--------------.\n"
        "| .---------\\         /----------------- \\         /------------. |\n"
        "| |          `-`--`--'                    `--'--'-'             | |\n"
        "| |   		1. Create Account details  	 			            | |\n"
        "| |		    2. Generate Random Password  (not saved)		    | |\n"
        "| |   		3. View Accounts                            		| |\n"
        "| |		    4. Exit                        					    | |\n"
        "| |		    5. Killswitch                                       | |\n"
        "| |         6. Print database                                   | |\n"
        "| |                                                             | |\n"
        "| |                                                             | |\n"
        "| |_____________________________________________________________| |\n"
        "|_________________________________________________________________| \n"
        "                   )__________|__|__________(\n"
        "                  |            ||            |\n"
        "                  |____________||____________|\n"
        "                    ),-----.(      ),-----.(\n"
        "                  ,'   ==.   \\    /  .==    `.\n"
        "                 /            )  (            \\\n"
        "                 `===========/'    `===========/'\033[0m\n"
    )
    print(menu)

# Test the function

def main():
    global encryption_key
    connection = sqlite3.connect(DATABASE_FILE)
    create_tables(connection)
    load_or_generate_encryption_key()
    create_master_account(connection, encryption_key)
    welcome_message()

    # Authenticate master account before allowing access
    if not authenticate_master_account(connection, encryption_key):
        print("Exiting program.")
        connection.close()
        return

    try:
        while True:
            print_menu()
            choice = input("Enter your choice (1, 2, 3, 4 or 5): ")

            if choice == '1':
                username = input("\nEnter the username for the account: ")
                medium = input("Enter the medium (e.g., Facebook, Instagram): ")

                # Ask the user for the password
                password = input("Enter the password for the account: ")

                # Save the hashed password in the accounts table
                hashed_password = save_account(connection, username, password, medium, encryption_key)

                print(
                    f"\nGenerated and Saved Account:\n  Username: {username}, Hashed Password: {hashed_password}, Medium: {medium}")

            elif choice == '2':
                generate_random_password()
            elif choice == '3':
                view_accounts(connection)
            elif choice == '4':
                print("\nExiting program.")
                connection.close()
                break
            elif choice == '5':
                wipe_all_data(connection, encryption_key)
            elif choice == '6':
                print_database_contents(connection)
            else:
                print("\nInvalid choice. Please enter 1, 2, 3, 4, or 5.")

            input("\nPress Enter to continue...")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    finally:
        connection.close()


if __name__ == "__main__":
    main()