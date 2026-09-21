import socket

HOST = "127.0.0.1"
PORT = 5000

for i in range(1, 11):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((HOST, PORT))

        request = (
            f"GET /login?username=test{i} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        client.sendall(request.encode("utf-8"))

        response = client.recv(4096).decode("utf-8")

        status_line = response.split("\r\n")[0]

        print(f"Request {i}: {status_line}")

    except Exception as error:
        print(f"Request {i}: Error - {error}")

    finally:
        client.close()