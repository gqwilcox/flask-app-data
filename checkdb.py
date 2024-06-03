import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect(r'C:\Users\gqwil\PycharmProjects\flask-app-data\test-authentication\instance\users.db')

# Create a cursor object to execute SQL queries
cursor = conn.cursor()

# Create a table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS user (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    phonenumber TEXT,
                    activationcode TEXT,
                    email TEXT,
                    password TEXT
                )''')

# Insert data into the table
data = [
    ('John', 'Doe', '123456', 'johndoe', 'password123'),
    ('Jane', 'Smith', '789012', 'janesmith', 'password456')
]
cursor.executemany('INSERT INTO user (name, phonenumber, activationcode, email, password) VALUES (?, ?, ?, ?, ?)', data)

# Commit the transaction
conn.commit()

# Fetch and print the inserted rows
cursor.execute("SELECT * FROM user")
rows = cursor.fetchall()
for row in rows:
    print(row)

# Close the cursor and connection
cursor.close()
conn.close()
