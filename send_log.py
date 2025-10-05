import requests

server_ip = "192.168.1.10"  # Flask server IP
url = f"http://{server_ip}:5000/api/log"

data = {
    "source": "Office-PC",
    "level": "INFO",
    "message": "This log came from another computer!"
}

response = requests.post(url, json=data)
print(response.status_code, response.text)
