import sqlite3
import os
import time
from datetime import datetime


# -------------------------------------------------
# Function to display dashboard
# -------------------------------------------------

def display_dashboard():

    # Clear terminal screen
    os.system("cls")

    # Connect to database
    connection = sqlite3.connect("security_logs.db")
    cursor = connection.cursor()


    # -------------------------------------------------
    # Get total requests
    # -------------------------------------------------

    cursor.execute("""
    SELECT COUNT(*)
    FROM security_logs
    """)

    total = cursor.fetchone()[0]


    # -------------------------------------------------
    # Get allowed requests
    # -------------------------------------------------

    cursor.execute("""
    SELECT COUNT(*)
    FROM security_logs
    WHERE action = 'ALLOWED'
    """)

    allowed = cursor.fetchone()[0]


    # -------------------------------------------------
    # Get blocked requests
    # -------------------------------------------------

    cursor.execute("""
    SELECT COUNT(*)
    FROM security_logs
    WHERE action = 'BLOCKED'
    """)

    blocked = cursor.fetchone()[0]


    # -------------------------------------------------
    # Display dashboard
    # -------------------------------------------------

    print("==============================================")
    print("          NETWORK SECURITY DASHBOARD")
    print("==============================================")

    # Live current time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("Current Time     :", current_time)

    print()
    # -------------------------------------------------
# Calculate attack rate
# -------------------------------------------------

    if total > 0:
     attack_rate = (blocked / total) * 100
    else:
     attack_rate = 0


    print("Total Requests   :", total)
    print("Allowed Requests :", allowed)
    print("Blocked Requests :", blocked)
    print("Attack Rate      :", round(attack_rate, 2), "%")

    print()
    print("==============================================")
    print("          RECENT SECURITY EVENTS")
    print("==============================================")


    # -------------------------------------------------
    # Get latest 5 requests
    # -------------------------------------------------

    cursor.execute("""
    SELECT timestamp, client_ip, request, prediction, action
    FROM security_logs
    ORDER BY id DESC
    LIMIT 5
    """)

    recent_logs = cursor.fetchall()


    # -------------------------------------------------
    # Display latest requests
    # -------------------------------------------------

    for log in recent_logs:

        timestamp, ip, request, prediction, action = log

        print()
        print("Event Time :", timestamp)
        print("Client IP  :", ip)
        print("Prediction :", prediction)
        print("Action     :", action)
        print("----------------------------------------------")


    connection.close()


# -------------------------------------------------
# Continuously refresh dashboard
# -------------------------------------------------

while True:

    display_dashboard()

    # Refresh every 1 second
    time.sleep(5)