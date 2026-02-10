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
        "DropTable","DropSchema","CreateSchema","CreateTable","InsertIntoTable"
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

#  Define the sensitive columns
target_columns := {"card_number", "customer_id"}

# 1. Masking Rule: Only for sensitive columns, and NOT system columns
column_masks := {"expression": "'****'"} {
    input.action.operation == "GetColumnMask"
    not is_admin
    target_columns[input.action.resource.column.columnName]
    not startswith(input.action.resource.column.columnName, "$")
}

# 2. Identity Rule: Only for non-sensitive columns, and NOT system columns
column_masks := {"expression": col_name} {
    input.action.operation == "GetColumnMask"
    col_name := input.action.resource.column.columnName
    
    # Do not mask if it's a system column
    not startswith(col_name, "$")
    
    # Run this block if it's NOT a sensitive column OR if the user IS an admin
    # This logic replaces the 'else' keyword
    is_identity_needed(col_name)
}

is_identity_needed(col) { not target_columns[col] }
is_identity_needed(col) { is_admin }

# 3. CRITICAL DEFAULT
# If the column is $partition, none of the above rules match.
# OPA returns 'undefined', which is exactly what Trino needs to proceed.
default column_masks := null
