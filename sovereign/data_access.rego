package sovereign.data_access

# This is required for the "some group in ..." syntax
import future.keywords.in
# import future.keywords.if

default allow = false


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

column_masks[{"expression": mask_expr}] {
    input.action.operation == "GetColumnMask"
    not is_admin  # Admin sees raw data; others see masks

    # Targeted Masking
    target_columns := {"card_number", "customer_id", "fraud_flag"}
    target_columns[input.action.resource.column.columnName]
    
    mask_expr := "'****-****-****-****'"

    # input.action.resource.column.columnName == "card_number"
    # mask_expr := "'****-****-****-****'"
}

# --- Column Masks (FIXED FOR TRINO 474) ---
# We use a single-value rule. If no conditions match, it returns 'undefined' (null),
# which Trino treats as "No Masking".
column_masks := {"expression": mask_expr} {
    input.action.operation == "GetColumnMask"
    not is_admin 

    # Targeted Masking
    target_columns := {"card_number", "customer_id", "fraud_flag"}
    target_columns[input.action.resource.column.columnName]
    
    mask_expr := "'****'"
}

is_admin {
  input.context.identity.user == "admin"
}
