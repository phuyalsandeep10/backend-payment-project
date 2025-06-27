# Team App

This app manages teams within the system.

## Models

### Team

- `name`: The name of the team.
- `team_lead`: A foreign key to the User who is the lead of the team.
- `members`: A many-to-many relationship with Users who are members of the team.
- `projects`: A many-to-many relationship with Projects assigned to the team.
- `contact_number`: The contact number for the team.
- `created_at`: Timestamp of when the team was created.
- `updated_at`: Timestamp of the last update. 