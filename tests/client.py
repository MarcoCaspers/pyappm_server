# Test client for the Python application manager server

import hashlib
from pathlib import Path
from requests import Session, Response  # type: ignore
from typing import Any, Callable

BASE_URL = "http://localhost:8000/api/v1"


def show_response(response: Response) -> None:
    print()
    print(f"Response status code: {response.status_code}")
    print(f"Response headers: {response.headers}")
    if response.status_code == 200:
        print(f"Response body: {response.json()}")
    elif response.status_code == 422:
        print()
        print("Validation errors:")
        errors = response.json()["detail"]
        for error in errors:
            if error.get("type") == "missing":
                print(f"Missing field: {error['loc'][1]}")
            else:
                print(f"Error: {error['msg']}")
    else:
        print(f"Response body: {response.text}")

    print()


def show_request(request: dict) -> None:
    print()
    print(f"Request method: {request['method']}")
    print(f"Request URL: {request['url']}")
    print(f"Request headers: {request['headers']}")
    if request["params"]:
        print(f"Request params: {request['params']}")
    if request["data"]:
        print(f"Request data: {request['data']}")
    if request["files"]:
        print(f"Request file: {request['files']}")
    print()


def execute_request(
    method: str,
    url: str,
    token: str | None = None,
    params: dict | None = None,
    data: dict | None = None,
    logged_in: bool = False,
    file: dict | None = None,
) -> Response:
    if url != f"{BASE_URL}/apps/add":
        headers = {"accept": "application/json"}
    else:
        headers = {}
    if logged_in and token:
        headers["Authorization"] = f"Bearer {token}"
    with Session() as session:
        # request = {
        #    "method": method,
        #    "url": url,
        #    "headers": headers,
        #    "params": params,
        #    "data": data,
        #    "files": file,
        # }
        # show_request(request)
        response = session.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            files=file,
        )
        return response


def test_server_connection() -> bool:
    response = execute_request("GET", BASE_URL)
    assert response.status_code == 200
    return True


def test_server_response() -> None:
    response = execute_request("GET", BASE_URL)
    assert response.json() == {"message": "Python application manager server"}


def test_server_health() -> None:
    response = execute_request("GET", f"{BASE_URL}/health")
    assert response.json() == {
        "message": "Python application manager server is healthy"
    }


def test_login_connection(username: str, password: str) -> None:
    response = execute_request(
        "POST",
        f"{BASE_URL}/login",
        data={"username": username, "password": password},
    )
    assert response.status_code == 200


def get_access_token(username: str, password: str) -> str:
    response = execute_request(
        "POST",
        f"{BASE_URL}/login",
        data={"username": username, "password": password},
    )
    # show_response(response)
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    return response.json()["access_token"]


def get_otp_token(access_token: str, otp_code: str) -> str:
    response = execute_request(
        "POST",
        f"{BASE_URL}/otp/validate",
        params={"totp_code": otp_code},
        token=access_token,
        logged_in=True,
    )
    # show_response(response)
    assert response.status_code == 200
    assert response.json()["otp_valid"] == True
    return response.json()["access_token"]


def test_get_users(token: str) -> dict:
    response = execute_request(
        "GET", f"{BASE_URL}/admin/users", token=token, logged_in=True
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    return response.json()


def test_get_user(token: str, user_id: int) -> dict:
    response = execute_request(
        "GET", f"{BASE_URL}/admin/users/{user_id}", token=token, logged_in=True
    )
    assert response.status_code == 200
    assert isinstance(response.json(), dict)
    return response.json()


def test_get_apps_by_owner_id(token: str, user_id: int) -> dict:
    response = execute_request(
        "GET", f"{BASE_URL}/admin/users/{user_id}/apps", token=token, logged_in=True
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    return response.json()


def test_find_app(app: str) -> list:
    response = execute_request(
        "GET", f"{BASE_URL}/apps/find/{app}", token=None, logged_in=True
    )
    # show_response(response)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    return response.json()


def test_logout(token: str) -> None:
    response = execute_request("GET", f"{BASE_URL}/logout", token=token, logged_in=True)
    assert response.status_code == 200


def test_get_apps_list() -> dict:
    response = execute_request(
        "GET", f"{BASE_URL}/apps/list", token=None, logged_in=False
    )
    assert response.status_code == 200
    # show_response(response)
    return response.json()


def run_test(func: Callable, *args) -> Any:
    try:
        result = func(*args)
        print(f"{func.__name__} passed")
        return result
    except AssertionError:
        print(f"{func.__name__} failed")
        return False


def calculate_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    if not file_path.exists():
        raise FileNotFoundError(f"File {file_path.name} not found")
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def upload_file_test(file_path: Path, token: str) -> None:
    """
    app information dictionary:
    {
        id (integer) or Id (null) (Id)
        owner_id required integer (Owner Id)
        name required string (Name)
        type required string (Type)
        version required string (Version)
        description Description (string) or Description (null) (Description)
        created_at Created At (string) or Created At (null) (Created At)
        updated_at Updated At (string) or Updated At (null) (Updated At)
    }
    """
    sha_256 = calculate_sha256(file_path)
    app_info = {
        "owner_id": 1,
        "name": "testfile",
        "type": "test",
        "version": "1.0",
        "description": "Test file",
        "sha_256": sha_256,
    }

    response = execute_request(
        method="POST",
        url=f"{BASE_URL}/apps/add",
        token=token,
        params=None,
        data=app_info,
        logged_in=True,
        file={
            "file": (file_path.name, open(file_path, "rb"), "application/octet-stream")
        },
    )
    show_response(response)
    assert response.status_code == 200


def show_file_info(file_info: dict) -> None:
    """_summary_

    Args:
        file_info (dict): _description_

            file_name=file_path.name,
            file_size=file_path.stat().st_size,
            file_type="application/octet-stream",
            file_sha256=await calculate_sha256(file_path),
            file=file_path.read_bytes(),
    """
    print()
    print("File information:")
    print(f"Name: {file_info['file_name']}")
    print(f"Content-Type: {file_info['file_type']}")
    print(f"Size: {file_info['file_size']} bytes")
    print(f"SHA-256: {file_info['file_sha256']}")
    print(f"Version: {file_info['app_version']}")
    print(f"Type: {file_info['app_type']}")
    print(f"Description: {file_info['description']}")
    print(f"Created at: {file_info['created_at']}")
    print(f"Updated at: {file_info['updated_at']}")
    print()


def download_file_test(app_name: str, version: str | None = None) -> None:
    app_version = {"version": version} if version else None
    response = execute_request(
        "GET",
        f"{BASE_URL}/apps/get/{app_name}",
        data=app_version,
        token=None,
        logged_in=False,
    )
    assert response.status_code == 200
    file_info = response.json()
    show_file_info(file_info)
    content: bytes = bytes(file_info["file"], "utf-8")
    with open(f"downloads/{file_info['file_name']}", "wb") as f:
        f.write(content)
    sha_256 = calculate_sha256(Path(f"downloads/{file_info['file_name']}"))
    assert sha_256 == file_info["file_sha256"]


def run_client_tests() -> None:
    connected = run_test(test_server_connection)
    if not connected:
        print("Server not connected, cannot run tests.")
        return
    run_test(test_server_response)
    run_test(test_server_health)
    run_test(test_login_connection, "marco@0xc007.nl", "SecurePassword")
    access_token = run_test(get_access_token, "marco@0xc007.nl", "SecurePassword")
    if access_token == False:
        print("Invalid login, cannot run tests.")
        return
    otp_code = input("Enter OTP code: ")
    otp_token = run_test(get_otp_token, access_token, otp_code)
    if otp_token == False:
        print("Invalid OTP code, cannot run tests.")
        return
    users = run_test(test_get_users, otp_token)
    user = run_test(test_get_user, otp_token, users[0]["id"])
    apps_list = run_test(test_get_apps_list)
    apps_by_owner_id = run_test(test_get_apps_by_owner_id, otp_token, user["id"])
    app = run_test(test_find_app, apps_list[0]["name"])
    run_test(upload_file_test, Path("tests/testfile.txt").absolute(), otp_token)
    run_test(test_logout, otp_token)
    print("All tests ran.")


if __name__ == "__main__":
    # run_client_tests()
    download_file_test("testfile")
