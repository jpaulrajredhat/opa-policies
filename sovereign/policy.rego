package trino.access

default allow = false

# ------------------------
# ACTION DERIVATION
# ------------------------

is_read {
  input.operation == "SelectFromColumns"
}

is_write {
  input.operation == "InsertIntoTable"
}

# ------------------------
# BASE ACCESS
# ------------------------

allow {
  is_read
  same_domain
  purpose_allowed
}

same_domain {
  input.identity.groups[_] == input.context.jwt.claims.department
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

# ------------------------
# MODEL TRAINING GUARD
# ------------------------

deny_reason := msg {
  is_read
  input.context.jwt.claims.purpose != "model_training"
  msg := "Access denied: purpose not allowed for training"
}
