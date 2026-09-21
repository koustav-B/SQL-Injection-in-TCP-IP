import sqlite3
import matplotlib.pyplot as plt


# -------------------------------------------------
# Connect to database
# -------------------------------------------------

connection = sqlite3.connect("security_logs.db")
cursor = connection.cursor()


# -------------------------------------------------
# Get prediction statistics
# -------------------------------------------------

cursor.execute("""
SELECT prediction, COUNT(*)
FROM security_logs
GROUP BY prediction
""")

results = cursor.fetchall()


# -------------------------------------------------
# Prepare data
# -------------------------------------------------

labels = []
counts = []

for prediction, count in results:

    labels.append(prediction)
    counts.append(count)


# -------------------------------------------------
# Create bar chart
# -------------------------------------------------

plt.bar(labels, counts)

plt.title("ML Prediction Statistics")

plt.xlabel("Prediction")

plt.ylabel("Number of Requests")


# -------------------------------------------------
# Display values on bars
# -------------------------------------------------

for i, count in enumerate(counts):

    plt.text(
        i,
        count,
        str(count),
        ha="center",
        va="bottom"
    )


# -------------------------------------------------
# Show graph
# -------------------------------------------------

plt.show()


# -------------------------------------------------
# Close database
# -------------------------------------------------

connection.close()