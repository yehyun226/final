# -*- coding: utf-8 -*-
import streamlit as st
import pandas as pd
import pymysql
from datetime import datetime

# ==========================================
# DB CONNECT
# ==========================================
def get_connection():
    return pymysql.connect(
        host=st.secrets["MYSQL_HOST"],
        user=st.secrets["MYSQL_USER"],
        password=st.secrets["MYSQL_PASSWORD"],
        database=st.secrets["MYSQL_DATABASE"],
        port=int(st.secrets["MYSQL_PORT"]),
        cursorclass=pymysql.cursors.DictCursor
    )


# ==========================================
# DB EXECUTE FUNCTION
# ==========================================
def execute_query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(sql, params or ())
    result = None

    if fetchone:
        result = cur.fetchone()
    elif fetchall:
        result = cur.fetchall()

    if commit:
        conn.commit()

    cur.close()
    conn.close()
    return result


# ==========================================
# PASSWORD CHECK
# ==========================================
import bcrypt

def check_password(raw, hashed):
    return bcrypt.checkpw(raw.encode("utf-8"), hashed.encode("utf-8"))


# ==========================================
# LOGIN & AUTH
# ==========================================
def login_screen():
    st.title("🔐 QMS 로그인")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("로그인"):
        sql = "SELECT * FROM users WHERE username=%s"
        user = execute_query(sql, (username,), fetchone=True)

        if not user:
            st.error("존재하지 않는 사용자입니다.")
            return

        if check_password(password, user["password_hash"]):
            st.session_state["user"] = user
            st.success("로그인 성공!")
            st.experimental_rerun()
        else:
            st.error("비밀번호가 올바르지 않습니다.")


def require_role(roles):
    user = st.session_state.get("user")
    if not user or user["role"] not in roles:
        st.error("접근 권한이 없습니다.")
        st.stop()


# ==========================================
# DASHBOARD
# ==========================================
def page_dashboard():
    st.header("📊 Dashboard")

    cc = execute_query("SELECT COUNT(*) AS cnt FROM change_controls", fetchone=True)["cnt"]
    dv = execute_query("SELECT COUNT(*) AS cnt FROM deviations", fetchone=True)["cnt"]
    cp = execute_query("SELECT COUNT(*) AS cnt FROM capas", fetchone=True)["cnt"]
    ra = execute_query("SELECT COUNT(*) AS cnt FROM risk_assessment", fetchone=True)["cnt"]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("변경관리", cc)
    col2.metric("일탈관리", dv)
    col3.metric("CAPA", cp)
    col4.metric("위험평가", ra)

    st.info("좌측 사이드바에서 메뉴를 선택하세요.")


# ==========================================
# CHANGE CONTROL
# ==========================================
def page_change_control():
    st.header("📝 변경관리 (Change Control)")

    tab1, tab2 = st.tabs(["등록된 변경관리", "새 변경관리 생성"])

    # LIST
    with tab1:
        rows = execute_query("SELECT * FROM change_controls ORDER BY id DESC", fetchall=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    # CREATE
    with tab2:
        title = st.text_input("Title")
        description = st.text_area("Description")
        requester = st.text_input("Requester")

        if st.button("생성"):
            sql = """
                INSERT INTO change_controls (title, description, requester, status)
                VALUES (%s, %s, %s, 'Draft')
            """
            execute_query(sql, (title, description, requester), commit=True)
            st.success("등록되었습니다.")
            st.experimental_rerun()


# ==========================================
# DEVIATIONS
# ==========================================
def page_deviations():
    st.header("⚠️ 일탈관리 (Deviation)")

    tab1, tab2 = st.tabs(["등록된 일탈", "새 일탈 생성"])

    # LIST
    with tab1:
        rows = execute_query("SELECT * FROM deviations ORDER BY id DESC", fetchall=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    # CREATE
    with tab2:
        deviation_id = st.text_input("Deviation ID")
        batch_id = st.text_input("Batch ID")
        description = st.text_area("Description")
        immediate_action = st.text_area("Immediate Action")
        root_cause = st.text_area("Root Cause")

        if st.button("일탈 등록"):
            sql = """
                INSERT INTO deviations (deviation_id, batch_id, description, immediate_action, root_cause, status)
                VALUES (%s, %s, %s, %s, %s, 'Open')
            """
            execute_query(sql, (deviation_id, batch,args(batch_id, description, immediate_action, root_cause)), commit=True)
            st.success("일탈이 생성되었습니다.")
            st.experimental_rerun()


# ==========================================
# CAPA
# ==========================================
def page_capa():
    st.header("🛠 CAPA")

    tab1, tab2 = st.tabs(["CAPA 목록", "새 CAPA 생성"])

    # LIST
    with tab1:
        rows = execute_query("SELECT * FROM capas ORDER BY id DESC", fetchall=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    # CREATE
    with tab2:
        capa_id = st.text_input("CAPA ID")
        action_plan = st.text_area("Action Plan")
        corrective_action = st.text_area("Corrective Action")
        preventive_action = st.text_area("Preventive Action")

        if st.button("CAPA 생성"):
            sql = """
                INSERT INTO capas (capa_id, action_plan, corrective_action, preventive_action, progress)
                VALUES (%s, %s, %s, %s, 'Not Started')
            """
            execute_query(sql, (capa_id, action_plan, corrective_action, preventive_action), commit=True)
            st.success("CAPA 생성 완료")
            st.experimental_rerun()


# ==========================================
# RISK ASSESSMENT
# ==========================================
def page_risk_assessment():
    st.header("📌 품질위험관리 (Risk Assessment)")

    tab1, tab2 = st.tabs(["위험 평가 목록", "새 위험평가 생성"])

    with tab1:
        rows = execute_query("SELECT * FROM risk_assessment ORDER BY id DESC", fetchall=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    with tab2:
        title = st.text_input("Title")
        description = st.text_area("Description")
        impact = st.text_area("Impact")
        risk_level = st.selectbox("Risk Level", ["Low", "Medium", "High"])

        if st.button("위험평가 생성"):
            sql = """
                INSERT INTO risk_assessment (title, description, impact, risk_level)
                VALUES (%s, %s, %s, %s)
            """
            execute_query(sql, (title, description, impact, risk_level), commit=True)
            st.success("위험평가가 등록되었습니다.")
            st.experimental_rerun()


# ==========================================
# USER MANAGEMENT (ADMIN ONLY)
# ==========================================
def page_users():
    require_role(["ADMIN"])
    st.header("👤 사용자 관리 (ADMIN 전용)")

    tabs = st.tabs(["사용자 목록", "새 사용자 생성"])

    # LIST
    with tabs[0]:
        rows = execute_query("SELECT id, username, role, created_at FROM users", fetchall=True)
        st.dataframe(pd.DataFrame(rows))

    # CREATE
    with tabs[1]:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["OPERATOR", "QA", "QC", "ADMIN"])

        if st.button("사용자 생성"):
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            sql = "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)"
            execute_query(sql, (username, hashed, role), commit=True)
            st.success("사용자 생성 완료")
            st.experimental_rerun()


# ==========================================
# MAIN
# ==========================================
def main():
    if "user" not in st.session_state:
        login_screen()
        return

    st.sidebar.title("QMS 메뉴")

    menu = st.sidebar.radio("Menu", [
        "Dashboard",
        "Change Control",
        "Deviations",
        "CAPA",
        "Risk Assessment",
        "Users (Admin)"
    ])

    if menu == "Dashboard":
        page_dashboard()
    elif menu == "Change Control":
        page_change_control()
    elif menu == "Deviations":
        page_deviations()
    elif menu == "CAPA":
        page_capa()
    elif menu == "Risk Assessment":
        page_risk_assessment()
    elif menu == "Users (Admin)":
        page_users()


if __name__ == "__main__":
    main()
