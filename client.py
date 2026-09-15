import socket

HOST = "127.0.0.1"
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

message = input("Enter request: ")

client.send(message.encode())

response = client.recv(4096).decode()

print("Server response:", response)

client.close()