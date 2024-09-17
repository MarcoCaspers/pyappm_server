from requests import session, Response  # type: ignore
from typing import Any, Callable

BASE_URL = "http://localhost:8000/api/v1"


def show_response(response: Response) -> None:
    print(f"Response status code: {response.status_code}")
    print(f"Response headers: {response.headers}")
    if response.status_code == 200:
        print(f"Response body: {response.json()}")
    else:
        print(f"Response text: {response.text}")


def execute_request(
    method: str,
    url: str,
    token: str | None = None,
    params: dict | None = None,
    data: dict | None = None,
    logged_in: bool = False,
) -> Response:
    headers = {"accept": "application/json"}
    if logged_in and token:
        headers["Authorization"] = f"Bearer {token}"
    with session() as client:
        response = client.request(
            method,
            url,
            params=params,
            headers=headers,
            data=data,
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


def test_get_apps_list() -> dict:
    response = execute_request(
        "GET", f"{BASE_URL}/apps/list", token=None, logged_in=True
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)
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
    show_response(response)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    return response.json()


def test_logout(token: str) -> None:
    response = execute_request("GET", f"{BASE_URL}/logout", token=token, logged_in=True)
    assert response.status_code == 200


def run_test(func: Callable, *args) -> Any:
    try:
        result = func(*args)
        print(f"{func.__name__} passed")
        return result
    except AssertionError:
        print(f"{func.__name__} failed")
        return False


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
    run_test(test_logout, otp_token)
    print("All tests ran.")


if __name__ == "__main__":
    # run_client_tests()
    url = f"{BASE_URL}/apps/list"
    print("GET", url)
    response = execute_request("GET", url, token=None, logged_in=False)
    show_response(response)
