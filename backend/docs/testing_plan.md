# User & Team Management Testing Plan

This document outlines the test cases for the user and team management features, specifically from the perspective of an `Organization Admin`.

## 1. Prerequisites

### 1.1. Create Test Users

First, we need to ensure we have the necessary user accounts for testing. This can be done via the Django admin panel or by using the API with `SUPER_ADMIN` credentials.

*   **Super Admin**: `superadmin`
*   **Organization Admin**: `org_admin_A` (assigned to "Organization A")
*   **Regular User**: `test_user_A` (assigned to "Organization A")
*   **Another Regular User**: `test_user_B` (assigned to "Organization B")

### 1.2. Log in as Organization Admin

All subsequent tests will be performed while authenticated as `org_admin_A`.

*   **Action:** Log in to the system using the credentials for `org_admin_A`.
*   **Expected Result:** The user is successfully authenticated and receives an auth token.

---

## 2. Commission Operation (Conceptual)

This step represents the business process that an `ORG_ADMIN` must complete before they are expected to manage users and teams.

*   **Action:** The `org_admin_A` user navigates to the commission section of the application and successfully completes a commission-related task (e.g., calculates and finalizes a commission report).
*   **Expected Result:** The commission task is completed successfully. This step is a conceptual prerequisite for the user management tasks that follow.

---

## 3. User Management Tests

These tests verify that an `ORG_ADMIN` can correctly manage users within their own organization.

### 3.1. List and View Users

*   **Test Case:** `ORG_ADMIN` can view all users within their organization.
*   **Action:** Make a `GET` request to `/api/auth/users/`.
*   **Expected Result:** The API returns a list of users. The list should include `org_admin_A` and `test_user_A`, but **not** `test_user_B` (who is in a different organization).

*   **Test Case:** `ORG_ADMIN` can use filters to search for users.
*   **Action:** Make a `GET` request to `/api/auth/users/?full_name=test`.
*   **Expected Result:** The API returns a list containing `test_user_A`.

### 3.2. Create a New User

*   **Test Case:** `ORG_ADMIN` can create a new user within their organization.
*   **Action:** Make a `POST` request to `/api/auth/users/` with the details of a new user. The new user should be assigned to "Organization A".
*   **Expected Result:** The API returns a `201 Created` status, and the new user is successfully created.

*   **Test Case:** `ORG_ADMIN` **cannot** create a new user in a different organization.
*   **Action:** Make a `POST` request to `/api/auth/users/` with the details of a new user, but attempt to assign them to "Organization B".
*   **Expected Result:** The API returns a `403 Forbidden` or `400 Bad Request` status.

### 3.3. Update a User

*   **Test Case:** `ORG_ADMIN` can update a user within their organization.
*   **Action:** Make a `PATCH` request to `/api/auth/users/{test_user_A_id}/` to update the user's `contact_number`.
*   **Expected Result:** The API returns a `200 OK` status, and the user's details are updated.

*   **Test Case:** `ORG_ADMIN` can deactivate a user.
*   **Action:** Make a `PATCH` request to `/api/auth/users/{test_user_A_id}/` to set `is_active` to `false`.
*   **Expected Result:** The user is now marked as inactive.

*   **Test Case:** `ORG_ADMIN` **cannot** update a user in a different organization.
*   **Action:** Make a `PATCH` request to `/api/auth/users/{test_user_B_id}/`.
*   **Expected Result:** The API returns a `404 Not Found` or `403 Forbidden` status.

---

## 4. Team Management Tests

These tests verify that an `ORG_ADMIN` can correctly manage teams and their members.

### 4.1. List and View Teams

*   **Test Case:** `ORG_ADMIN` can view all teams within their organization.
*   **Action:** Make a `GET` request to `/api/teams/`.
*   **Expected Result:** The API returns a list of teams that have members from "Organization A".

### 4.2. Create a New Team

*   **Test Case:** `ORG_ADMIN` can create a new team.
*   **Action:** Make a `POST` request to `/api/teams/` with a name for the new team.
*   **Expected Result:** The API returns a `201 Created` status. The `org_admin_A` user should automatically be added as a member of the new team.

### 4.3. Update a Team

*   **Test Case:** `ORG_ADMIN` can add members to a team.
*   **Action:** Make a `PATCH` request to `/api/teams/{team_id}/` to add `test_user_A` to the `members` list.
*   **Expected Result:** The API returns a `200 OK` status, and the user is now a member of the team.

*   **Test Case:** `ORG_ADMIN` can assign a team lead.
*   **Action:** Make a `PATCH` request to `/api/teams/{team_id}/` to set `team_lead` to `org_admin_A`.
*   **Expected Result:** The `org_admin_A` user is now the lead of the team.

*   **Test Case:** `ORG_ADMIN` can assign projects to a team.
*   **Action:** Make a `PATCH` request to `/api/teams/{team_id}/` to add a project to the `projects` list.
*   **Expected Result:** The project is now assigned to the team.

*   **Test Case:** `ORG_ADMIN` **cannot** add a user from another organization to a team.
*   **Action:** Attempt to `PATCH` a team to add `test_user_B` as a member.
*   **Expected Result:** The API returns a `400 Bad Request` because the user is not in the same organization.

--- 