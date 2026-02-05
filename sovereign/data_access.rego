package sovereign.data_access

default allow = false

# --- Helpers ---
is_read { input.action.operation == "SelectFromColumns" }
is_execute { input.action.operation == "ExecuteQuery" }
is_metadata { input.action.operation == "AccessCatalog" }

# --- Base Access ---
allow { is_execute }
allow { is_metadata }

allow {
  is_read
  # Matches any group starting with /fraud
  startswith(input.context.identity.groups[_], "/fraud")
}

# --- Sovereign Row Filter ---
row_filter = expr {
  is_read
  # 1. Grab the group (e.g., "/fraud:IN")
  group := input.context.identity.groups[_]
  startswith(group, "/fraud:")
  
  # 2. Split the string to get "IN"
  # split("/fraud:IN", ":") -> ["/fraud", "IN"]
  parts := split(group, ":")
  region := parts[1]
  
  # 3. Apply the filter
  expr := sprintf("region = '%s'", [region])
}

# --- Column Masking ---
column_mask["amount"] = "NULL" {
  is_read
  not is_admin
}

is_admin {
  input.context.identity.user == "admin"
}
