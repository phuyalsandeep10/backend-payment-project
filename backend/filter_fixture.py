import json

SUPERADMIN_EMAIL = "shishirkafle18@gmail.com"
ORGADMIN_EMAIL = "applicants.brahmabytelab@gmail.com"
ORG_ID_TO_KEEP = 43
ORG_ADMIN_ROLE_PK = 56

with open("all_data.json") as f:
    data = json.load(f)

# Update the org admin's email for role 56 in org 43
for obj in data:
    if (
        obj["model"] == "authentication.user"
        and obj["fields"].get("organization") == ORG_ID_TO_KEEP
        and obj["fields"].get("role") == ORG_ADMIN_ROLE_PK
    ):
        obj["fields"]["email"] = ORGADMIN_EMAIL

# Step 1: Collect all users in org 43 and the superadmin
user_ids_to_keep = set()
for obj in data:
    if obj["model"] == "authentication.user":
        if obj["fields"].get("organization") == ORG_ID_TO_KEEP:
            user_ids_to_keep.add(obj.get("pk", obj.get("id")))
        if obj["fields"]["email"] == SUPERADMIN_EMAIL:
            user_ids_to_keep.add(obj.get("pk", obj.get("id")))

# Step 2: Collect all related objects for org 43
org_related_ids = {
    "organization": set([ORG_ID_TO_KEEP]),
    "team": set(),
    "role": set(),
    "client": set(),
    "deal": set(),
    "commission": set(),
}

for obj in data:
    if obj["model"] == "team.team" and obj["fields"].get("organization") == ORG_ID_TO_KEEP:
        org_related_ids["team"].add(obj.get("pk", obj.get("id")))
    if obj["model"] == "permissions.role" and obj["fields"].get("organization") == ORG_ID_TO_KEEP:
        org_related_ids["role"].add(obj.get("pk", obj.get("id")))
    if obj["model"] == "clients.client" and obj["fields"].get("organization") == ORG_ID_TO_KEEP:
        org_related_ids["client"].add(obj.get("pk", obj.get("id")))
    if obj["model"] == "deals.deal" and obj["fields"].get("organization") == ORG_ID_TO_KEEP:
        org_related_ids["deal"].add(obj.get("pk", obj.get("id")))
    if obj["model"] == "commission.commission" and obj["fields"].get("organization") == ORG_ID_TO_KEEP:
        org_related_ids["commission"].add(obj.get("pk", obj.get("id")))

# Step 3: Filter the data
def keep(obj):
    if obj["model"] == "authentication.user":
        return obj.get("pk", obj.get("id")) in user_ids_to_keep
    if obj["model"] == "organization.organization":
        return obj.get("pk", obj.get("id")) == ORG_ID_TO_KEEP
    if obj["model"] == "team.team":
        return obj.get("pk", obj.get("id")) in org_related_ids["team"]
    if obj["model"] == "permissions.role":
        return obj.get("pk", obj.get("id")) in org_related_ids["role"]
    if obj["model"] == "clients.client":
        return obj.get("pk", obj.get("id")) in org_related_ids["client"]
    if obj["model"] == "deals.deal":
        return obj.get("pk", obj.get("id")) in org_related_ids["deal"]
    if obj["model"] == "commission.commission":
        return obj.get("pk", obj.get("id")) in org_related_ids["commission"]
    # Remove authtoken.Token with null user
    if obj["model"] == "authtoken.token":
        if obj["fields"].get("user") is None:
            print(f"Skipping authtoken.Token with null user: {obj}")
            return False
        return True
    # Always keep contenttypes, permissions, groups, etc.
    if obj["model"].startswith("contenttypes.") or obj["model"].startswith("auth.") or obj["model"].startswith("sessions.") or obj["model"].startswith("authtoken."):
        return True
    return False

filtered = [obj for obj in data if keep(obj)]

with open("initial_data.json", "w") as f:
    json.dump(filtered, f, indent=2)

print("Filtered fixture written to initial_data.json") 