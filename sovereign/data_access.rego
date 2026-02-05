package sovereign.data_access

default allow = false

# ------------------------
# ACTION DERIVATION
# ------------------------

# Fix: Trino sends this as input.action.operation
is_read {
  input.action.operation == "SelectFromColumns"
}

is_write {
  input.action.operation == "InsertIntoTable"
}

# Fix: You MUST allow ExecuteQuery or the query never starts
is_execute {
  input.action.operation == "ExecuteQuery"
}

# ------------------------
# BASE ACCESS
# ------------------------

# Allow the initial query handshake
allow {
  is_execute
}

allow {
  is_read
  same_domain
  purpose_allowed
}

# Fix: Based on your log, identity is inside context
same_domain {
  input.context.identity.groups[_] == input.context.jwt.claims.department
}

purpose_allowed {
  input.context.jwt.claims.purpose == "model_training"
}

# ------------------------
# SOVEREIGN ROW FILTER
# ------------------------

row_filter = expr {
  is_read
  region := input.context.jwt.claims.sovereign_region
  expr := sprintf("region = '%s'", [region])
}

# ------------------------
# COLUMN MASKING
# ------------------------

column_mask["amount"] = "NULL" {
  is_read
  input.context.jwt.claims.clearance != "high"
}

