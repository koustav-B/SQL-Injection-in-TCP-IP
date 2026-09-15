import socket
import pickle

# Load trained model
with open("sqli_model.pkl", "rb") as file:
    model = pickle.load(file)

# Load TF-IDF vectorizer
with open("tfidf_vectorizer.pkl", "rb") as file:
    vectorizer = pickle.load(file)


HOST = "127.0.0.1"
PORT = 5000

# Create TCP socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((HOST, PORT))
server.listen(5)

print("Server started...")
print("Waiting for client connection...")

while True:

    client_socket, client_address = server.accept()

    client_ip = client_address[0]
    client_port = client_address[1]

    print("\nClient connected!")
    print("Client IP:", client_ip)
    print("Client Port:", client_port)

    # Receive data
    data = client_socket.recv(4096).decode()

    print("Received:", data)

    # Convert request into TF-IDF
    data_tfidf = vectorizer.transform([data])

    # Predict
    prediction = model.predict(data_tfidf)[0]

    print("Prediction:", prediction)

    # Allow or block
    if prediction == "anom":

        response = "SQL Injection detected! Request BLOCKED."

        print("Action: BLOCKED")

    else:

        response = "Normal request. Request ALLOWED."

        print("Action: ALLOWED")

    # Send response to client
    client_socket.send(response.encode())

    # Close connection
    client_socket.close()