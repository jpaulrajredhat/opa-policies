package sovereign.data_access

# This is required for the "some group in ..." syntax
import future.keywords.in
# import future.keywords.if

default allow = false

# 1. Provide a default so 'not is_admin' is predictable
default is_admin := false

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

# ---  Column Masks (FIXED: Default to null) ---
default column_masks = null

column_masks := {"expression": mask_expr} {
    input.action.operation == "GetColumnMask"
    
    # Logic to determine the expression
    mask_expr := get_mask_expression(is_admin, input.action.resource.column.columnName)
}

# --- CHANGE 3: Logic Helper ---
# If admin, the expression is the column name itself (no masking)
get_mask_expression(true, col_name) = col_name

# If NOT admin, and it's a sensitive column, return '****'
get_mask_expression(false, col_name) = "'****'" {
    target_columns := {"card_number", "customer_id", "fraud_flag"}
    target_columns[col_name]
}

# If NOT admin, but NOT a sensitive column, return the column name itself
get_mask_expression(false, col_name) = col_name {
    target_columns := {"card_number", "customer_id", "fraud_flag"}
    not target_columns[col_name]
}

is_admin {
  input.context.identity.user == "admin"
}
