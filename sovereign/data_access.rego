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

#  Define the sensitive columns
target_columns := {"card_number", "customer_id"}

#  Complete Column Masking Logic using 'else'
# This rule is "Complete" (assigned with :=), so only one block will ever run.

column_masks := {"expression": "'****'"} {
    # IF: It's a masking request
    input.action.operation == "GetColumnMask"
    
    # AND: The user is NOT an admin
    not is_admin 

    # AND: The column is in our sensitive list
    target_columns[input.action.resource.column.columnName]

} else := {"expression": col_name} {
    # ELSE: Return the original column name (Identity Mask)
    # This block runs for Admins OR for non-sensitive columns
    input.action.operation == "GetColumnMask"
    col_name := input.action.resource.column.columnName
}

#  Optional: Default to null for non-masking operations
default column_masks := null
