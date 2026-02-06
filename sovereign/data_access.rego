package sovereign.data_access

# This is required for the "some group in ..." syntax
import future.keywords.in
import future.keywords.if

default allow = false


# --- 1. Enhanced Table-to-Column Mapping ---
# Format: "catalogName.schemaName.tableName": "filterColumn"
table_filter_columns := {
    # "iceberg.single_family.loans": "region",
    "postgresql.public.credit_card_transactions_combined": "region"
    # "mysql.sales.customers": "state"
}

# --- Helpers ---
is_read { input.action.operation == "SelectFromColumns" }
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
row_filters contains {"expression": expr} if {
    is_read
    
    # A) Construct the full path from the Trino resource object
    # Based on your log: input.action.resource.table.catalogName, etc.
    res := input.action.resource.table
    full_path := sprintf("%s.%s.%s", [res.catalogName, res.schemaName, res.tableName])
    
    # B) Lookup the column for THIS specific catalog/table
    filter_column := table_filter_columns[full_path]
    
    # C) Extract region (e.g., "/fraud/IN" -> "IN")
    some group in input.context.identity.groups
    startswith(group, "/fraud/")
    parts := split(group, "/")
    region_value := parts[2]
    
    # D) Build the SQL
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
