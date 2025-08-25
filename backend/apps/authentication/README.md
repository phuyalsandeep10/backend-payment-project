# Authentication App

This app is responsible for user management, authentication, and roles within the Payment Receiving System. It features a custom user model to handle different user roles, such as `SUPER_ADMIN` and `ORG_ADMIN`.

## File Structure and Purpose

-   `__init__.py`: Marks this directory as a Python package.
-   `admin.py`: (Not yet implemented) Will be used to register the custom User model with the Django admin site.
-   `apps.py`: Contains the application configuration for the `authentication` app.
-   `management/commands/`: Holds custom management commands. `create_super_admin.py` is a command to initialize a super administrator.
-   `migrations/`: Stores the database migration files for the custom User model.
-   `models.py`: Defines the custom `User` model, which extends Django's `AbstractUser`.
-   `tests.py`: For writing unit and integration tests for authentication functionality.
-   `urls.py`: Defines the URL routing for authentication endpoints, such as login.
-   `views.py`: Contains the logic for authentication views, like handling user login.

## Database Design

The `authentication` app introduces a custom `User` model:

### `User` (extends `AbstractUser`)

| Field        | Type            | Description                                                  |
|--------------|-----------------|--------------------------------------------------------------|
| `role`       | `CharField`     | The user's role, chosen from `SUPER_ADMIN` or `ORG_ADMIN`. |
| `organization`| `ForeignKey`    | A link to the `Organization` the user belongs to (can be null). |

This custom user model replaces Django's default user model to provide more flexibility and support the role-based access control required by the application. 