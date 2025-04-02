import sqlite3
import os

def initialize_database():
    if not os.path.exists("users.db"):
        connection = sqlite3.connect("users.db")
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'admin123'))
        connection.commit()
        connection.close()
        print("Database initialized with a default admin user.")

def register_user(username, password):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        connection.commit()
        print("User registered successfully!")
    except sqlite3.IntegrityError:
        print("Error: Username already exists!")
    connection.close()

def login(username, password):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    
    # Secure SQL Query using parameterized queries
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    
    if user:
        print(f"Welcome back, {username}!")
    else:
        print("Invalid username or password.")
    
    connection.close()

def main():
    initialize_database()
    while True:
        print("\nMenu:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            username = input("Enter a username: ")
            password = input("Enter a password: ")
            register_user(username, password)
        elif choice == '2':
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            login(username, password)
        elif choice == '3':
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
