import sqlite3

connection = sqlite3.connect("security_logs.db")
cursor = connection.cursor()
cursor.execute("SELECT * FROM security_logs")
logs = cursor.fetchall()

for log in logs:
    print(log)

connection.close()