package sovereign.data_access

# This is required for the "some group in ..." syntax
import future.keywords.in

default allow = false

# --- 1. Table-to-Column Mapping ---
# Define which column should be used for filtering on each table
# Format: "tableName": "filterColumn"
table_filter_columns := {
    # "loans": "region",
    # "us_customers": "property_state",
    # "eu_transactions": "country_code"
    "credit_card_transactions_combined": "region"
    
}

# --- Helpers ---
is_read { input.action.operation == "SelectFromColumns" }
is_execute { input.action.operation == "ExecuteQuery" }
# is_metadata { input.action.operation == "AccessCatalog" }
is_metadata { 
    
    ops := {
        "AccessCatalog", "AccessSchema", "AccessTable", 
        "FilterCatalogs", "FilterSchemas", "FilterTables",
        "ShowCatalogs", "ShowSchemas", "ShowTables",
        "DropTable"
    }
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
# row_filter = expr {
#    is_read
#    # 1. Find the group that contains the region (e.g., "/fraud/IN")
#    some group in input.context.identity.groups
#    startswith(group, "/fraud/")
    
#    # 2. Extract "IN" by splitting "/fraud/IN" into ["", "fraud", "IN"]
#    parts := split(group, "/")
#    region := parts[2] 
    
#   # 3. Apply the filter
#    expr := sprintf("region = '%s'", [region])
#}

# ---  Dynamic Row Filter ---
row_filter = expr {
    is_read
    
    # A) Identify the table being queried
    table_name := input.action.resource.table.tableName
    
    # B) Get the correct column for this table from our map
    filter_column := table_filter_columns[table_name]
    
    # C) Extract the region value from the group (e.g., "/fraud/IN" -> "IN")
    some group in input.context.identity.groups
    startswith(group, "/fraud/")
    parts := split(group, "/")
    region_value := parts[2]
    
    # D) Build the SQL: "region = 'IN'" or "property_state = 'IN'"
    expr := sprintf("%s = '%s'", [filter_column, region_value])
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
