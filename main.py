import sqlite3
import random
import string

DATABASE_FILE = "passwords.db"
                                        # needed
def create_table():
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                      (identifier TEXT PRIMARY KEY, password TEXT)''')
    connection.commit()
    connection.close()

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

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def save_password(identifier, password):
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()
    cursor.execute("INSERT OR REPLACE INTO passwords (identifier, password) VALUES (?, ?)", (identifier, password))
    connection.commit()
    connection.close()

def load_passwords():
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM passwords")
    passwords = {row[0]: row[1] for row in cursor.fetchall()}
    connection.close()
    return passwords

def view_passwords():
    passwords = load_passwords()

    if not passwords:
        print("No passwords found.")
    else:
        print("\nStored Passwords:")
        for identifier, password in passwords.items():
            print(f"  {identifier}: {password}")

def main():
    create_table()

    while True:
        print("\nMenu:")
        print("1. Generate Password")
        print("2. View Passwords")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == '1':
            identifier = input("\nEnter an identifier for the password: ")
            password = generate_password()
            save_password(identifier, password)
            print(f"\nGenerated Password for {identifier}: {password}")
        elif choice == '2':
            view_passwords()
        elif choice == '3':
            print("\nExiting program.")
            break
        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
