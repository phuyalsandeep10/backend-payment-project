# How to Add Clients in Bulk

This document explains how to use the `add_clients` management command to add multiple clients to a specific organization from a CSV file.

## 1. Prepare Your CSV File

Create a CSV file with the following columns (headers are required):
- `client_name`
- `email`
- `phone_number`

**Example (`example_clients.csv`):**
```csv
client_name,email,phone_number
"Innovate Inc.","contact@innovate.com","+15550001"
"Quantum Solutions","hello@quantum.io","+15550002"
"Stellar Corp","main@stellarcorp.net","+15550003"
```

## 2. Find the Organization and User IDs

You need to know two IDs before running the script:
- The ID of the **organization** you want to add clients to.
- The ID of the **salesperson** (`user`) who should be listed as the creator of these clients.

You can find these in the Django admin panel or by using the shell.

**Example (Django Shell):**
```bash
python backend/manage.py shell
```
```python
from organization.models import Organization
from authentication.models import User

# Find your Organization ID
print(Organization.objects.values('id', 'name'))
# <QuerySet [{'id': 1, 'name': 'Apex Innovations'}, ...]>

# Find your User ID within that organization
print(User.objects.filter(organization_id=1).values('id', 'email'))
# <QuerySet [{'id': 15, 'email': 'sales@apex.com'}, ...]>
```
From the output, find the `id` of your target organization and the `id` of the user.

## 3. Run the Command

Use the `add_clients` command with the organization ID, the user ID, and the path to your CSV file.

**Command Syntax:**
```bash
python backend/manage.py add_clients <organization_id> <user_id> --csv <path_to_your_csv_file>
```

**Example Usage:**

Let's say you want to add clients to organization `1` and assign them to user `15`:

```bash
python backend/manage.py add_clients 1 15 --csv backend/example_clients.csv
```

## 4. Review the Output

The script will print its progress, confirming which user the clients are being assigned to.

**Example Output:**
```
Found organization: 'Apex Innovations'
Assigning new clients to user: 'sales@apex.com'
Successfully added client: 'Innovate Inc.' (contact@innovate.com)
Successfully added client: 'Quantum Solutions' (hello@quantum.io)
Client with email 'contact@innovate.com' already exists for this organization. Skipping.
--------------------
Script finished.
Clients added: 2
Clients skipped: 1
```

## Important Notes

- **Duplicates:** The script uses the combination of `email` and `organization` to identify duplicates. It will not create a new client if another client with the same email already exists in the target organization.
- **`created_by` User:** The script now **requires** you to specify the `user_id` of the salesperson creating the clients. This ensures correct ownership from the start.
- **Validation:** The script validates each client's data against the model's validators (e.g., for the phone number format) and that the specified user belongs to the specified organization. 