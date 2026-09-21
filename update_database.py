import sqlite3


# -------------------------------------------------
# Connect to existing database
# -------------------------------------------------

connection = sqlite3.connect("security_logs.db")
cursor = connection.cursor()


# -------------------------------------------------
# Add request_size column
# -------------------------------------------------

try:

    cursor.execute("""
    ALTER TABLE security_logs
    ADD COLUMN request_size INTEGER
    """)

    print("request_size column added successfully!")

except sqlite3.OperationalError:

    print("request_size column already exists.")


# -------------------------------------------------
# Save changes
# -------------------------------------------------

connection.commit()
connection.close()