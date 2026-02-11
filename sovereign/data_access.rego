package sovereign.data_access

# This is required for the "some group in ..." syntax
import future.keywords.in
# import future.keywords.if

# --- 1. Identity & Helpers ---
default is_admin := false
is_admin {
    input.context.identity.user == "admin"
}

is_system_col(name) { startswith(name, "$") }

# --- 2. Base Access Control ---
default allow := false

# Power Rule: Admin can do anything (prevents "Access Denied" on metadata/procedures)
allow if is_admin

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
    # ops := {"SelectFromColumns", "GetRowFilters"}
    ops := {"SelectFromColumns", "GetRowFilters","ShowColumns", "FilterColumns", "AccessTable", "DescribeTable", "AccessCatalog", "AccessSchema"}
    ops[input.action.operation]
}
is_execute { input.action.operation == "ExecuteQuery" }

is_metadata { 
    
    ops := {
        "AccessCatalog", "AccessSchema", "AccessTable", "DescribeTable",
        "FilterCatalogs", "FilterSchemas", "FilterTables", "FilterColumns",
        "ShowCatalogs", "ShowSchemas", "ShowTables", "ShowColumns",
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

# Rule: Mask sensitive data only for non-admins during SELECTs
column_masks := {"expression": "'****'"} {
    input.action.operation == "GetColumnMask"
    not is_admin
    not is_system_col(input.action.resource.column.columnName)
    target_columns[input.action.resource.column.columnName]
}

# Rule: Identity mask for safe columns (Non-admins only)
column_masks := {"expression": col_name} {
    input.action.operation == "GetColumnMask"
    col_name := input.action.resource.column.columnName
    not is_admin
    not is_system_col(col_name)
    not target_columns[col_name]
}

# 3. CRITICAL DEFAULT
# If the column is $partition, none of the above rules match.
# OPA returns 'undefined', which is exactly what Trino needs to proceed.
default column_masks := null
