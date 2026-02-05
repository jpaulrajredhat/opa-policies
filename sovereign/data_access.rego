package sovereign.data_access

# This is required for the "some group in ..." syntax
import future.keywords.in

default allow = false

# --- Helpers ---
is_read { input.action.operation == "SelectFromColumns" }
is_execute { input.action.operation == "ExecuteQuery" }
# is_metadata { input.action.operation == "AccessCatalog" }
is_metadata { 
    ops := {"AccessCatalog", "AccessSchema", "AccessTable"}
    ops[input.action.operation]
}

# --- Base Access ---
allow { is_execute }
allow { is_metadata }

allow {
  is_read
  # Matches any group starting with /fraud
  # startswith(input.context.identity.groups[_], "/fraud")
  # Checks if any group is exactly "/fraud" or starts with "/fraud/"
  some group in input.context.identity.groups
  startswith(group, "/fraud")
}

# --- Sovereign Row Filter ---
row_filter = expr {
    is_read
    # 1. Find the group that contains the region (e.g., "/fraud/IN")
    some group in input.context.identity.groups
    startswith(group, "/fraud/")
    
    # 2. Extract "IN" by splitting "/fraud/IN" into ["", "fraud", "IN"]
    parts := split(group, "/")
    region := parts[2] 
    
    # 3. Apply the filter
    expr := sprintf("region = '%s'", [region])
}

# --- Column Masking ---
column_mask["amount"] = "NULL" {
    is_read
    input.context.identity.user != "admin"
}

# --- Column Masking ---
# column_mask["amount"] = "NULL" {
#  is_read
#  not is_admin
#}

is_admin {
  input.context.identity.user == "admin"
}
