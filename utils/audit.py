from railway_mysql import execute_query

def log_action(user_id, action_type, object_type, object_id,
               field_name=None, old_value=None, new_value=None):
    sql = """
    INSERT INTO audit_logs
    (user_id, action_type, object_type, object_id,
     field_name, old_value, new_value)
    VALUES (%s,%s,%s,%s,%s,%s,%s)
    """
    params = (user_id, action_type, object_type, object_id,
              field_name, old_value, new_value)
    execute_query(sql, params, commit=True)
