package sovereign.data_access

default allow = false

# --- Helpers ---
is_read { input.action.operation == "SelectFromColumns" }
is_execute { input.action.operation == "ExecuteQuery" }
is_metadata { input.action.operation == "AccessCatalog" }

# --- Base Access ---
allow { is_execute }
allow { is_metadata } # Added this! Essential for query planning

allow {
  is_read
  # Fix: Use the group found in the logs ["/fraud"] instead of jwt.claims
  input.context.identity.groups[_] == "/fraud"
}

# --- Sovereign Row Filter ---
row_filter = expr {
  is_read
  # Since we don't have the JWT region yet, hardcode 'IN' to verify it works
  # or map it from the group if possible
  expr := "region = 'IN'"
}

# --- Column Masking ---
column_mask["amount"] = "NULL" {
  is_read
  # If we can't see JWT clearance, default to masking for safety
  not is_admin
}

is_admin {
  input.context.identity.user == "admin"
}

