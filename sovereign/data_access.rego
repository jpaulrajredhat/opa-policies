package sovereign.data_access

# This is required for the "some group in ..." syntax
import future.keywords.in
# import future.keywords.if

default allow = false

# 1. Provide a default so 'not is_admin' is predictable
default is_admin := false
is_admin := true {
    input.context.identity.user == "admin"
}


# --- 1. Enhanced Table-to-Column Mapping ---
# Format: "catalogName.schemaName.tableName": "filterColumn"
table_filter_columns := {
    # "iceberg.single_family.loans": "region",
    "postgres.public.credit_card_transactions_combined": "region"
    # "mysql.sales.customers": "state"
}

# --- Helpers ---
# is_read { input.action.operation == "SelectFromColumns" }
is_read { 
    ops := {"SelectFromColumns", "GetRowFilters"}
    ops[input.action.operation]
}
is_execute { input.action.operation == "ExecuteQuery" }

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

# --- Multiple Catalog Row Filter ---
row_filters[{"expression": expr}] {
    is_read

    not is_admin 
    # 1. Construct the full path
    res := input.action.resource.table
    full_path := sprintf("%s.%s.%s", [res.catalogName, res.schemaName, res.tableName])
    
    # 2. Lookup column
    filter_column := table_filter_columns[full_path]
    
    # 3. Extract region
    some group in input.context.identity.groups
    startswith(group, "/fraud/")
    parts := split(group, "/")
    region_value := parts[2]
    
    # 4. Build SQL
    expr := sprintf("%s = '%s'", [filter_column, region_value])
}

target_columns := {"card_number", "customer_id"}

# RULE 1: Apply the Mask
# Triggers ONLY for non-admins on sensitive columns
column_masks := {"expression": "'****'"} {
    input.action.operation == "GetColumnMask"
    not is_admin
    target_columns[input.action.resource.column.columnName]
}

# RULE 2: Return the Column (No Mask)
# Triggers for Admins OR non-admins on safe columns
column_masks := {"expression": col} {
    input.action.operation == "GetColumnMask"
    col := input.action.resource.column.columnName
    
    # This helper ensures Rule 1 and Rule 2 never run at the same time
    is_exempt(is_admin, col)
}

# Helper: Defines who is exempt from masking
is_exempt(true, _)        # Admins are always exempt
is_exempt(false, col) {   # Non-admins are exempt if column is not sensitive
    not target_columns[col]
}
