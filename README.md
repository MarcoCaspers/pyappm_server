# Pyappm server

## Description

Pyappm server is a RESTful API server for the Pyappm project. It is a Python FastAPI application that provides endpoints.

## Installation

### Prerequisites

- Python 3.10 or higher
- FastAPI
- Uvicorn
- Pydantic
- Pyotp
- qrcode
- python-jose
- passlib
- bcrypt
- requests

(See [requirements.txt](requirements.txt) for more details)

### Installation steps

1. Create a new user and group for the service:

```bash
sudo useradd -r -s /bin/false pyappm_server
```

2. Download the installation package:

```bash
wget https://pyappm.nl/downloads/pyappm_server.zip
```

3. Unzip the package:

```bash
sudo unzip pyappm_server.zip -d /etc/pyappm_server
```

4. Perform the following steps:

```bash
sudo -i
cd /etc/pyappm_server
mkdir data
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
deactivate
exit
```

5. Change the owner of the installation directory:

```bash
sudo chown -R pyappm_server:pyappm_server /etc/pyappm_server
```

6. Copy the service file to the systemd directory:

```bash
sudo cp /etc/pyappm_server/pyappm_server.service /etc/systemd/system/
```

7. Reload the systemd daemon:

```bash
sudo systemctl daemon-reload
```

8. Enable the service:

```bash
sudo systemctl enable pyappm_server
```

9. Start the service:

```bash
sudo systemctl start pyappm_server
```

10. Check the status of the service:

```bash
sudo systemctl status pyappm_server
```


