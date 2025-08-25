# API URL Guide

This document provides a comprehensive guide to the API endpoints available in the PRS backend. All API endpoints are prefixed with `/api/v1/`.

The API is organized into several resources, each with its own set of endpoints.

---

## 1. Authentication (`/api/v1/auth/`)

Handles user authentication, registration, and profile management.

| Method(s)                         | URL Path                    | View Name                      | Description                                        |
|-----------------------------------|-----------------------------|--------------------------------|----------------------------------------------------|
| `POST`                            | `/auth/login/`              | `authentication:direct_login`  | Logs a user in and returns an authentication token.  |
| `POST`                            | `/auth/logout/`             | `authentication:logout`        | Logs a user out and invalidates their token.       |
| `POST`                            | `/auth/register/`           | `authentication:register`      | Registers a new user.                              |
| `POST`                            | `/auth/password/change/`    | `authentication:password_change` | Allows an authenticated user to change their password.|
| `GET`, `PUT`, `PATCH`             | `/auth/profile/`            | `authentication:profile`       | View and update the authenticated user's profile.    |
| `GET`, `POST`                     | `/auth/users/`              | `authentication:user-list`     | List users or create a new user (Admin only).      |
| `GET`, `PUT`, `PATCH`, `DELETE`   | `/auth/users/<pk>/`         | `authentication:user-detail`   | Retrieve, update, or delete a specific user (Admin only).|

---

## 2. Organizations (`/api/v1/organizations/`)

Manages organizations within the system.

| Method(s)                         | URL Path                     | View Name                   | Description                                          |
|-----------------------------------|------------------------------|-----------------------------|------------------------------------------------------|
| `POST`                            | `/organizations/register/`   | `organization-register`     | Public endpoint to register a new organization.      |
| `GET`, `POST`                     | `/organizations/`            | `organization-list`         | List all organizations or create a new one.          |
| `GET`, `PUT`, `PATCH`, `DELETE`   | `/organizations/<pk>/`       | `organization-detail`       | Retrieve, update, or delete a specific organization. |

---

## 3. Permissions & Roles (`/api/v1/permissions/`)

Manages user roles and their associated permissions.

| Method(s)                         | URL Path                     | View Name                   | Description                                          |
|-----------------------------------|------------------------------|-----------------------------|------------------------------------------------------|
| `GET`                             | `/permissions/all/`          | `permission-list`           | Lists all available permissions in the system.       |
| `GET`, `POST`                     | `/permissions/roles/`        | `role-list`                 | List all roles or create a new role.                 |
| `GET`, `PUT`, `PATCH`, `DELETE`   | `/permissions/roles/<pk>/`   | `role-detail`               | Retrieve, update, or delete a specific role.         |

---

## 4. Clients (`/api/v1/clients/`)

Handles client management.

| Method(s)                         | URL Path                     | View Name                   | Description                                          |
|-----------------------------------|------------------------------|-----------------------------|------------------------------------------------------|
| `GET`, `POST`                     | `/clients/`                  | `client-list`               | List all clients or create a new client.             |
| `GET`, `PUT`, `PATCH`, `DELETE`   | `/clients/<pk>/`             | `client-detail`             | Retrieve, update, or delete a specific client.       |

---

## 5. Projects (`/api/v1/projects/`)

Manages projects.

| Method(s)                         | URL Path                     | View Name                   | Description                                          |
|-----------------------------------|------------------------------|-----------------------------|------------------------------------------------------|
| `GET`, `POST`                     | `/projects/`                 | `project-list`              | List all projects or create a new one.               |
| `GET`, `PUT`, `PATCH`, `DELETE`   | `/projects/<pk>/`            | `project-detail`            | Retrieve, update, or delete a specific project.      |

---

## 6. Teams (`/api/v1/teams/`)

Manages teams.

| Method(s)                         | URL Path                     | View Name                   | Description                                          |
|-----------------------------------|------------------------------|-----------------------------|------------------------------------------------------|
| `GET`, `POST`                     | `/teams/`                    | `team-list`                 | List all teams or create a new team.                 |
| `GET`, `PUT`, `PATCH`, `DELETE`   | `/teams/<pk>/`               | `team-detail`               | Retrieve, update, or delete a specific team.         |

---

## 7. Deals (`/api/v1/deals/`)

Manages deals and their related activities and payments.

### Standalone Deal Endpoints

| Method(s)                         | URL Path                                 | View Name                   | Description                                          |
|-----------------------------------|------------------------------------------|-----------------------------|------------------------------------------------------|
| `GET`, `POST`                     | `/deals/deals/`                          | `deal-list`                 | List all deals or create a new deal.                 |
| `GET`, `PUT`, `PATCH`, `DELETE`   | `/deals/deals/<pk>/`                     | `deal-detail`               | Retrieve, update, or delete a specific deal.         |
| `GET`, `POST`                     | `/deals/deals/<deal_pk>/activity/`       | `deal-activity-list`        | List or create activity log entries for a deal.      |
| `GET`, `PUT`, `PATCH`, `DELETE`   | `/deals/deals/<deal_pk>/activity/<pk>/`  | `deal-activity-detail`      | Retrieve, update, or delete a specific activity log. |
| `GET`, `POST`                     | `/deals/deals/<deal_pk>/payments/`       | `deal-payments-list`        | List or create payments for a deal.                  |
| `GET`, `PUT`, `PATCH`, `DELETE`   | `/deals/deals/<deal_pk>/payments/<pk>/`  | `deal-payments-detail`      | Retrieve, update, or delete a specific payment.      |

### Nested Deal Endpoints (under Clients)

These endpoints provide contextual access to deals and related data for a specific client.

| Method(s) | URL Path                                       | View Name                     | Description                                          |
|-----------|------------------------------------------------|-------------------------------|------------------------------------------------------|
| `GET`     | `/clients/<client_pk>/deals/`                  | `client-deals-list`           | List all deals for a specific client.                |
| `GET`     | `/clients/<client_pk>/deals/<pk>/`             | `client-deals-detail`         | Retrieve a specific deal for a client.               |
| `GET`     | `/clients/<client_pk>/deals/<deal_pk>/activity/`| `client-deal-activity-list` | List activity logs for a specific deal of a client.  |
| `GET`     | `/clients/<client_pk>/deals/<deal_pk>/payments/`| `client-deal-payments-list` | List payments for a specific deal of a client.       |

---

## 8. Commission (`/api/v1/commission/`)

Manages commission records.

| Method(s)                         | URL Path                     | View Name                   | Description                                          |
|-----------------------------------|------------------------------|-----------------------------|------------------------------------------------------|
| `GET`, `POST`                     | `/commission/`               | `commission-list`           | List all commission records or create a new one.     |
| `GET`                             | `/commission/<pk>/`          | `commission-detail`         | Retrieve a specific commission record.               |

---

## 9. Notifications (`/api/v1/notifications/`)

Handles user notifications and settings.

| Method(s)                         | URL Path                                        | View Name                                | Description                                       |
|-----------------------------------|-------------------------------------------------|------------------------------------------|---------------------------------------------------|
| `GET`                             | `/notifications/notifications/`                 | `notifications:notification-list`        | List notifications for the authenticated user.    |
| `GET`                             | `/notifications/notifications/<pk>/`            | `notifications:notification-detail`      | Retrieve a specific notification.                 |
| `POST`                            | `/notifications/notifications/<pk>/mark_as_read/`| `notifications:notification-mark-as-read`| Mark a single notification as read.               |
| `POST`                            | `/notifications/notifications/mark_all_as_read/`| `notifications:notification-mark-all-as-read` | Mark all of the user's notifications as read.     |
| `GET`                             | `/notifications/notifications/stats/`           | `notifications:notification-stats`       | Get notification statistics for the user.         |
| `GET`                             | `/notifications/notifications/unread_count/`    | `notifications:notification-unread-count`| Get the count of unread notifications.            |
| `GET`, `PUT`, `PATCH`             | `/notifications/notification-settings/`         | `notifications:notification-settings-list` and `detail` | Get or update the user's notification settings. |

### Admin Notification Endpoints

| Method(s) | URL Path                                                       | View Name                                         | Description                                       |
|-----------|----------------------------------------------------------------|---------------------------------------------------|---------------------------------------------------|
| `GET`     | `/notifications/notification-admin/list_templates/`            | `notifications:notification-admin-list-templates` | List all notification templates.                  |
| `POST`    | `/notifications/notification-admin/create_template/`           | `notifications:notification-admin-create-template`| Create a new notification template.               |
| `POST`    | `/notifications/notification-admin/send_test_notification/`    | `notifications:notification-admin-send-test-notification` | Send a test notification to the current admin.    |

---

## 10. Sales Dashboard (`/api/v1/dashboard/`)

Provides endpoints for the sales dashboard analytics.

| Method(s) | URL Path                          | View Name                       | Description                               |
|-----------|-----------------------------------|---------------------------------|-------------------------------------------|
| `GET`     | `/dashboard/`                     | `sales_dashboard:dashboard`     | Main dashboard view with aggregated data. |
| `GET`     | `/dashboard/clients/`             | `sales_dashboard:clients`       | Client list for the dashboard.            |
| `GET`     | `/dashboard/commission/`          | `sales_dashboard:commission`    | Commission overview.                      |
| `GET`     | `/dashboard/standings/`           | `sales_dashboard:standings`     | Daily sales standings.                    |
| `GET`     | `/dashboard/streak/`              | `sales_dashboard:streak`        | View current user's sales streak.         |
| `GET`     | `/dashboard/streak/leaderboard/`  | `sales_dashboard:leaderboard`   | View the sales streak leaderboard.        |

---

## 11. API Documentation

| Method(s) | URL Path            | View Name             | Description                                          |
|-----------|---------------------|-----------------------|------------------------------------------------------|
| `GET`     | `/swagger/`         | `schema-swagger-ui`   | Interactive Swagger/OpenAPI documentation UI.        |
| `GET`     | `/redoc/`           | `schema-redoc`        | Alternative ReDoc documentation UI.                  |

--- 