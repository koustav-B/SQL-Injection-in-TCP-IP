import sqlite3


# -------------------------------------------------
# Connect to database
# -------------------------------------------------

connection = sqlite3.connect("security_logs.db")

cursor = connection.cursor()


# -------------------------------------------------
# Total number of requests
# -------------------------------------------------

cursor.execute("""
SELECT COUNT(*)
FROM security_logs
""")

total_requests = cursor.fetchone()[0]


# -------------------------------------------------
# Number of allowed requests
# -------------------------------------------------

cursor.execute("""
SELECT COUNT(*)
FROM security_logs
WHERE action = 'ALLOWED'
""")

allowed_requests = cursor.fetchone()[0]


# -------------------------------------------------
# Number of blocked requests
# -------------------------------------------------

cursor.execute("""
SELECT COUNT(*)
FROM security_logs
WHERE action = 'BLOCKED'
""")

blocked_requests = cursor.fetchone()[0]


# -------------------------------------------------
# Calculate attack percentage
# -------------------------------------------------

if total_requests > 0:
    attack_percentage = (blocked_requests / total_requests) * 100
else:
    attack_percentage = 0


# -------------------------------------------------
# Display statistics
# -------------------------------------------------

print("\n===================================")
print("       NETWORK TRAFFIC STATS")
print("===================================")

print("Total Requests    :", total_requests)
print("Allowed Requests  :", allowed_requests)
print("Blocked Requests  :", blocked_requests)
print("Attack Percentage :", round(attack_percentage, 2), "%")

print("===================================")
# -------------------------------------------------
# Protocol statistics
# -------------------------------------------------

cursor.execute("""
SELECT protocol, COUNT(*)
FROM security_logs
GROUP BY protocol
""")

protocol_stats = cursor.fetchall()


print("\nProtocol Statistics:")

for protocol, count in protocol_stats:
    print(protocol, ":", count)


# -------------------------------------------------
# Client IP statistics
# -------------------------------------------------

cursor.execute("""
SELECT client_ip, COUNT(*)
FROM security_logs
GROUP BY client_ip
ORDER BY COUNT(*) DESC
""")

ip_stats = cursor.fetchall()


print("\nClient IP Statistics:")

for ip, count in ip_stats:
    print(ip, ":", count)
    # -------------------------------------------------
# Prediction statistics
# -------------------------------------------------

cursor.execute("""
SELECT prediction, COUNT(*)
FROM security_logs
GROUP BY prediction
""")

prediction_stats = cursor.fetchall()


print("\nPrediction Statistics:")

for prediction, count in prediction_stats:
    print(prediction, ":", count)


# -------------------------------------------------
# Close database
# -------------------------------------------------

connection.close()