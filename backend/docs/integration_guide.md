# Frontend Integration Guide

Welcome to the **Payment Receiving System (PRS) API**. This guide provides all the necessary information for the frontend team to integrate with the backend services.

## Base URL

All API endpoints are prefixed with `/api/`. The full base URL will depend on the deployment environment. For local development, it is typically `http://127.0.0.1:8000/api/`.

## Authentication

The API uses token-based authentication. To access protected endpoints, you must include an `Authorization` header with your API requests.

**Header Format:**
`Authorization: Token <your_auth_token>`

### Obtaining an Auth Token

To get an authentication token, you need to use one of the login endpoints.

#### 1. Standard User Login

*   **Endpoint:** `POST /auth/login/`
*   **Description:** Authenticates a standard user and returns an auth token.
*   **Request Body:**
    ```json
    {
        "username": "testuser",
        "password": "testpassword123"
    }
    ```
*   **Response:**
    ```json
    {
        "token": "YOUR_AUTH_TOKEN",
        "user_id": 1,
        "email": "user@example.com",
        "role": "USER"
    }
    ```

#### 2. Super Admin Login (Two-Factor OTP)

Super admin login is a two-step process that uses a One-Time Password (OTP) sent to a secure, pre-configured email address.

**Step 1: Request OTP**
*   **Endpoint:** `POST /auth/super-admin/login/`
*   **Request Body:**
    ```json
    {
        "username": "superadmin",
        "password": "superadminpassword"
    }
    ```
*   **Response:**
    ```json
    {
        "message": "An OTP has been sent to the designated admin email. It is valid for 5 minutes."
    }
    ```

**Step 2: Verify OTP and Get Token**
*   **Endpoint:** `POST /auth/super-admin/verify/`
*   **Request Body:**
    ```json
    {
        "username": "superadmin",
        "otp": "123456"
    }
    ```
*   **Response:**
    ```json
    {
        "token": "YOUR_AUTH_TOKEN",
        "user_id": 1,
        "email": "superadmin@example.com",
        "role": "SUPER_ADMIN"
    }
    ```
---

## API Endpoints

### Users

The User endpoint allows for the management of user accounts.

*   **URL:** `/auth/users/`
*   **Permissions:**
    *   **Admin:** Full CRUD access.
    *   **Authenticated User:** Can list and view all users, but can only update their own account.
    *   **Unauthenticated User:** No access.

#### List Users (`GET /auth/users/`)

Returns a paginated list of all users.

**Filtering:**
The list endpoint supports filtering on the following query parameters:
*   `full_name`: Search for users by their first or last name (case-insensitive).
    *   Example: `/auth/users/?full_name=john`
*   `email`: Filter by exact email address.
*   `contact_number`: Filter by contact number.
*   `role`: Filter by user role (`SUPER_ADMIN`, `ORG_ADMIN`, `USER`).
*   `team`: Filter by the ID of the assigned team.

**Example Response:**
```json
[
    {
        "id": 1,
        "username": "johndoe",
        "first_name": "John",
        "last_name": "Doe",
        "email": "johndoe@example.com",
        "role": "USER",
        "organization": 1,
        "org_role": 2,
        "team": {
            "id": 1,
            "name": "Design Wizards"
        },
        "contact_number": "+1234567890",
        "is_active": true
    }
]
```

#### Retrieve a User (`GET /auth/users/{id}/`)

Returns the details of a specific user.

#### Create a User (`POST /auth/users/`)

Creates a new user. Only available to admins.

**Request Body:**
```json
{
    "username": "newuser",
    "password": "strongpassword123",
    "first_name": "New",
    "last_name": "User",
    "email": "newuser@example.com",
    "role": "USER",
    "organization": 1, // ID of the organization
    "org_role": 2, // ID of the organization role
    "team": 1, // ID of the team
    "contact_number": "+9876543210",
    "is_active": true
}
```

#### Update a User (`PUT /auth/users/{id}/` or `PATCH /auth/users/{id}/`)

Updates a user's details. Users can only update their own profile unless they are an admin.

---

### Teams

The Teams endpoint allows for the management of teams.

*   **URL:** `/api/teams/`
*   **Permissions:**
    *   **Admin or Team Lead:** Full CRUD access.
    *   **Authenticated User:** Read-only access.
    *   **Unauthenticated User:** No access.

#### List Teams (`GET /api/teams/`)

Returns a paginated list of all teams.

**Example Response:**
```json
[
    {
        "id": 1,
        "name": "Design Wizards",
        "team_lead": {
            "id": 2,
            "username": "teamlead",
            "first_name": "Team"
        },
        "members": [
            {
                "id": 3,
                "username": "member1",
                "first_name": "Member"
            }
        ],
        "projects": [
            {
                "id": 1,
                "name": "New UI/UX Revamp"
            }
        ],
        "contact_number": "+111222333",
        "created_at": "2023-10-27T10:00:00Z",
        "updated_at": "2023-10-27T10:00:00Z"
    }
]
```

#### Retrieve a Team (`GET /api/teams/{id}/`)

Returns the details of a specific team.

#### Create a Team (`POST /api/teams/`)

Creates a new team.

**Request Body:**
*   `name` (string, required): The name of the team.
*   `team_lead` (integer, required): The ID of the user who will be the team lead.
*   `members` (array of integers, required): A list of user IDs for the team members.
*   `projects` (array of integers, optional): A list of project IDs to assign to the team.
*   `contact_number` (string, optional): A contact number for the team.

**Example:**
```json
{
    "name": "New Development Team",
    "team_lead": 2,
    "members": [3, 4],
    "projects": [1],
    "contact_number": "+444555666"
}
```

#### Update a Team (`PUT /api/teams/{id}/` or `PATCH /api/teams/{id}/`)

Updates a team's details.

---

### Projects

The Projects endpoint is used to manage projects that can be assigned to teams.

*   **URL:** `/api/projects/`
*   **Permissions:**
    *   **Admin:** Full CRUD access.
    *   **Authenticated User:** Read-only access.
    *   **Unauthenticated User:** No access.

#### List Projects (`GET /api/projects/`)

Returns a paginated list of all projects.

**Example Response:**
```json
[
    {
        "id": 1,
        "name": "New UI/UX Revamp",
        "teams": [
            {
                "id": 1,
                "name": "Design Wizards"
            }
        ],
        "created_at": "2023-10-27T09:00:00Z",
        "updated_at": "2023-10-27T09:00:00Z"
    }
]
```

#### Retrieve a Project (`GET /api/projects/{id}/`)

Returns the details of a specific project.

#### Create a Project (`POST /api/projects/`)

Creates a new project. Only available to admins.

**Request Body:**
```json
{
    "name": "New Backend Feature"
}
```

#### Update a Project (`PUT /api/projects/{id}/` or `PATCH /api/projects/{id}/`)

Updates a project's details. Only available to admins. 