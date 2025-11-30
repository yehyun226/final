# pages/6_Audit_Trail.py
import streamlit as st
from railway_mysql import execute_query
from login import require_login, require_role

def app():
    require_login()
    # 필요하면 QA/ADMIN만 보게 제한
    # require_role(["QA","ADMIN"])

    st.title("Audit Trail")

    obj_type = st.text_input("Object Type 필터 (예: CHANGE, DEVIATION, CAPA, ATTACHMENT, RISK)", "")
    action_type = st.text_input("Action Type 필터 (예: CREATE, STATUS_CHANGE, UPLOAD)", "")

    sql = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    if obj_type:
        sql += " AND object_type=%s"
        params.append(obj_type)
    if action_type:
        sql += " AND action_type=%s"
        params.append(action_type)

    sql += " ORDER BY timestamp DESC LIMIT 500"

    rows = execute_query(sql, tuple(params), fetchall=True)
    st.dataframe(rows, use_container_width=True)

if __name__ == "__main__":
    app()
