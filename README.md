# Payment Receiving System (PRS) - Backend

This repository contains the backend for the Payment Receiving System (PRS), a multi-tenant application designed to manage payments for various organizations. It is built with Django and Django Rest Framework, providing a robust and secure API.

## Project Overview

The system is designed with a clear administrative hierarchy:

-   **Super Admins (`SUPER_ADMIN`):** Have top-level control over the entire system. They can create, manage, and oversee all organizations.
-   **Organization Admins (`ORG_ADMIN`):** Manage a single, specific organization. They are created and assigned to an organization by a Super Admin.

The backend provides API endpoints for all administrative functions, including user authentication, organization management, and admin creation.

## Tech Stack

-   **Framework:** Django
-   **API:** Django Rest Framework
-   **Database:** PostgreSQL
-   **Authentication:** Token-based authentication

## Local Development Setup

To run this project on your local machine, follow these steps:

### 1. Prerequisites

-   Python 3.10+
-   PostgreSQL installed and running
-   `pip` and `venv`

### 2. Clone the Repository

```bash
git clone <your-repository-url>
cd Backend_PRS
```

### 3. Set Up the Environment

Create a virtual environment to manage project dependencies:

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

Install the required packages:

```bash
pip install -r backend/requirements.txt
```

### 4. Configure the Database

1.  Create a PostgreSQL database for the project (e.g., `payment_db`).
2.  Create a `.env` file in the `backend/` directory by copying the example:

    ```bash
    cp backend/.env.example backend/.env
    ```

3.  Update the `backend/.env` file with your PostgreSQL database credentials:

    ```
    DB_NAME=your_db_name
    DB_USER=your_db_user
    DB_PASSWORD=your_db_password
    DB_HOST=localhost
    DB_PORT=5432
    ```

### 5. Run Database Migrations

Apply the database schema:

```bash
python backend/manage.py migrate
```

### 6. Create a Super Administrator

To access the administrative features, you need a super admin account. Set the following environment variables in your `.env` file:

```
ADMIN_USER=your_admin_username
ADMIN_EMAIL=your_admin_email@example.com
ADMIN_PASS=your_strong_password
```

Then, run the management command:

```bash
python backend/manage.py create_super_admin
```

### 7. Run the Development Server

Start the Django development server:

```bash
python backend/manage.py runserver
```

The API will be available at `http://127.0.0.1:8000/`.

## API Endpoints

-   **Authentication:** `/api/auth/`
-   **Organization Management:** `/api/org/`

All administrative endpoints under `/api/org/` require token authentication and `SUPER_ADMIN` privileges.