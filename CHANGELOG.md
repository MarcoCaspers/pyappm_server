# Pyappm Server CHANGELOG

## [1.0.0.a2] - 2024-08-18

- Started using CHANGELOG.md
- Added a new feature: commandline switch --db-file-path (-d) to specify the path to the database file, default is 'data/pyappm.db'
- Added a new feature: route /api/v1/admin/users/{user_id} to get a user by id
- Added client tests for the new route /api/v1/admin/users/{user_id}
- Added a new feature: route /api/v1/admin/users/{user_id}/apps to list all users of an app
- Added client tests for the new route /api/v1/admin/users/{user_id}/apps
- Added a new feature: route /api/v1/admin/apps/list to list all apps
- Added a new feature: route /api/v1/admin/apps/find/id/{app_id} to get an app by id (returns a single app or none, 404 error if not found)
- Added a new feature: route /api/v1/admin/apps/find/name/{app_name} to get an app by name (returns a list, empty list if not found)

## [1.0.0.a3] - 2024-09-11

- Restructured client tests, it now makes much more sense.
- Added endpoint /api/v1/apps/find/{app_name} to get an app by name (returns a list of app one entry per version or none, 404 error if not found)
- Added endpoint for server health. (GET /api/v1/health)
- Added endpoint for server version. (GET /api/v1/version)
- Reogranized routers.
- Added blacklisting of tokens for logged out users, and users that got a valid otp token.
- Added cleanup of blacklisted tokens.
- Added endpoint for logout. (POST /api/v1/logout)
- created .gitignore
- initialized git repository

## [1.0.0.a4] - 2024-09-11

- renamed install.py to pyappm_server_init.py
- updated README.md
- updated LICENSE.txt
- Added Makefile
- Changed pyappm_server executable into a shell script to be used with the service file.
- Added pyappm_server.service file for systemd
- Disabled docs and redocs in the FastAPI app

## [1.0.0.a5] - 2024-09-17

- Changed data directory long arg name to --data
- Updated startup code to better handle the data directory
