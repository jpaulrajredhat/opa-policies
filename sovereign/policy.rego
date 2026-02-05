package sovereign.policytest

default allow = false

# =============================
# INPUT CONTRACT
# =============================
# input.user.department
# input.user.deployment
# input.user.sovereign_region
# input.user.training_allowed
# input.resource.catalog
# input.resource.schema
# input.resource.table
# input.action  (read | train)

# =============================
# RULE: READ DATA
# =============================
allow {
  input.action == "read"

  input.user.department == input.resource.schema
  input.user.sovereign_region == data_region[input.resource.table]
}

# =============================
# RULE: MODEL TRAINING
# =============================
allow {
  input.action == "train"

  input.user.training_allowed == true
  input.user.deployment == "fraud-ml"

  input.user.sovereign_region == data_region[input.resource.table]
}

# =============================
# TABLE → REGION MAP
# (could come from OPAL data sync later)
# =============================
data_region := {
  "transactions_in": "IN",
  "transactions_eu": "EU",
  "transactions_us": "US"
}

