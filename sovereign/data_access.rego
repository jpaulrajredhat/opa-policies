package sovereign.data_access

# This is required for the "some group in ..." syntax
import future.keywords.in
# import future.keywords.if

# --- 1. Identity & Helpers ---
default is_admin := false
is_admin {
    input.context.identity.user == "admin"
}
# This allows Trino to read its own internal column/table definitions
is_system_metadata {
    input.action.resource.table.schema in {"information_schema", "system"}
}

allow {
    is_read
    is_system_metadata
}

allow {
    input.action.operation == "AccessCatalog"
}

# Define helpers to identify domains based on Trino catalogs/schemas
is_fraud_domain {
    # Replace 'fraud_catalog' with your actual Trino catalog name
    input.action.resource.table.catalogName == "postgres"
}
is_mortgage_domain {
    # Replace 'mortgage_catalog' with your actual Trino catalog name
    input.action.resource.table.catalogName == "iceberg"
}
is_system_col(name) { startswith(name, "$") }

# --- 2. Base Access Control ---
default allow := false

# Power Rule: Admin can do anything (prevents "Access Denied" on metadata/procedures)
# allow if is_admin

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

  is_fraud_domain
  is_read
  
  # Matches any group starting with /fraud
  # startswith(input.context.identity.groups[_], "/fraud")
  # Checks if any group is exactly "/fraud" or starts with "/fraud/"
  some group in input.context.identity.groups
  startswith(group, "/fraud")
}

# Rule 2: Mortgage group ONLY allowed to access Mortgage catalog (US only)
allow {
    is_mortgage_domain
    is_read
    # Keycloak attributes usually come under input.context.identity.extra
    # depending on your Trino/Keycloak mapper setup
    # input.context.identity.extra.country == "US"
    some group in input.context.identity.groups
    startswith(group, "/mortgage")
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


# --- 1. The "Write Bypass" Rule ---
# This allows the mortgage user to perform INSERTs without masking errors.
column_masks := null {
    # If the user is admin OR if this is an Insert operation, return null.
    is_admin
}

column_masks := null {
    # Some Trino versions check metadata during Insert; this ensures no mask is returned.
    input.action.operation == "InsertIntoTable"
}

# --- 2. The Sensitive Mask (Only for READS/SELECTS) ---
column_masks := {"expression": "'****'"} {
    not is_admin
    input.action.operation == "GetColumnMask"
    # Ensure we don't trigger this during an INSERT
    not input.action.operation == "InsertIntoTable"
    target_columns[input.action.resource.column.columnName]
}

# --- 3. The Identity Mask (Only for READS/SELECTS) ---
# This was the rule causing your specific failure!
column_masks := {"expression": col_name} {
    not is_admin
    input.action.operation == "GetColumnMask"
    not input.action.operation == "InsertIntoTable"
    col_name := input.action.resource.column.columnName
    not target_columns[col_name]
    not is_system_col(col_name)
}

# --- 4. Final Default ---
default column_masks := null
