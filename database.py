import sqlite3

connection = sqlite3.connect("security_logs.db")
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    client_ip TEXT,
    client_port INTEGER,
    protocol TEXT,
    request TEXT,
    request_size INTEGER,
    connection_duration REAL,
    prediction TEXT,
    action TEXT
)
""")

connection.commit()
connection.close()

print("Database created successfully!")