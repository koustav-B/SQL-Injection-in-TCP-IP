import sqlite3
import matplotlib.pyplot as plt


# -------------------------------------------------
# Connect to database
# -------------------------------------------------

connection = sqlite3.connect("security_logs.db")
cursor = connection.cursor()


# -------------------------------------------------
# Get allowed and blocked requests
# -------------------------------------------------

cursor.execute("""
SELECT action, COUNT(*)
FROM security_logs
GROUP BY action
""")

results = cursor.fetchall()


# -------------------------------------------------
# Separate values
# -------------------------------------------------

labels = []
counts = []

for action, count in results:
    labels.append(action)
    counts.append(count)


# -------------------------------------------------
# Create bar chart
# -------------------------------------------------

plt.bar(labels, counts)

plt.title("Network Request Analysis")

plt.xlabel("Action")

plt.ylabel("Number of Requests")


# -------------------------------------------------
# Display values on bars
# -------------------------------------------------

for i, count in enumerate(counts):
    plt.text(i, count, str(count), ha="center", va="bottom")


# -------------------------------------------------
# Show chart
# -------------------------------------------------

plt.show()


# -------------------------------------------------
# Close database
# -------------------------------------------------

connection.close()