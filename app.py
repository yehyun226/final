# -*- coding: utf-8 -*-
import os
from datetime import datetime

import streamlit as st
import pandas as pd
import pymysql
import bcrypt

# ==========================================
# 0. DB CONNECT (환경변수 기반 - 원래 버전 스타일)
# ==========================================
def get_connection():
    """
    Railway / 서버 환경에 설정된 환경변수 사용:
    MYSQL_HOST / MYSQL_PORT / MYSQL_USER / MYSQL_PASSWORD / MYSQL_DB
    """
    return pymysql.connect(
        host=os.environ["MYSQL_HOST"],
        user=os.environ["MYSQL_USER"],
        password=os.environ["MYSQL_PASSWORD"],
        database=os.environ["MYSQL_DB"],   # 원래 버전과 동일
        port=int(os.environ["MYSQL_PORT"]),
        cursorclass=pymysql.cursors.DictCursor,
        charset="utf8mb4",
        autocommit=True,
    )


# ==========================================
# 1. DB EXECUTE FUNCTION
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
# 2. PASSWORD UTILS
# ==========================================
def check_password(raw, hashed):
    return bcrypt.checkpw(raw.encode("utf-8"), hashed.encode("utf-8"))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


# ==========================================
# 3. LOGIN & AUTH
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
            # 세션에 필요한 정보만 저장
            st.session_state["user"] = {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            }
            st.success("로그인 성공!")
            st.experimental_rerun()
        else:
            st.error("비밀번호가 올바르지 않습니다.")


def require_login():
    if "user" not in st.session_state:
        st.warning("로그인이 필요합니다.")
        st.stop()


def require_role(roles):
    require_login()
    user = st.session_state["user"]
    if user["role"] not in roles:
        st.error("접근 권한이 없습니다.")
        st.stop()


# ==========================================
# 4. DASHBOARD
# ==========================================
def page_dashboard():
    require_login()
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
# 5. CHANGE CONTROL
# ==========================================
def page_change_control():
    require_login()
    user = st.session_state["user"]

    st.header("📝 변경관리 (Change Control)")

    tab1, tab2 = st.tabs(["등록된 변경관리", "새 변경관리 생성"])

    # LIST
    with tab1:
        rows = execute_query("SELECT * FROM change_controls ORDER BY id DESC", fetchall=True)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 변경관리가 없습니다.")

    # CREATE
    with tab2:
        title = st.text_input("Title")
        description = st.text_area("Description")
        requester = st.text_input("Requester", value=user["username"])

        if st.button("생성"):
            if not title or not description:
                st.warning("Title과 Description은 필수입니다.")
            else:
                sql = """
                    INSERT INTO change_controls (title, description, requester, status, created_at)
                    VALUES (%s, %s, %s, 'Draft', NOW())
                """
                execute_query(sql, (title, description, requester), commit=True)
                st.success("등록되었습니다.")
                st.experimental_rerun()


# ==========================================
# 6. DEVIATIONS
# ==========================================
def page_deviations():
    require_login()
    user = st.session_state["user"]

    st.header("⚠️ 일탈관리 (Deviation)")

    tab1, tab2 = st.tabs(["등록된 일탈", "새 일탈 생성"])

    # LIST
    with tab1:
        rows = execute_query("SELECT * FROM deviations ORDER BY id DESC", fetchall=True)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 일탈이 없습니다.")

    # CREATE
    with tab2:
        deviation_id = st.text_input("Deviation ID")
        batch_id = st.text_input("Batch ID")
        description = st.text_area("Description")
        immediate_action = st.text_area("Immediate Action")
        root_cause = st.text_area("Root Cause")

        if st.button("일탈 등록"):
            if not deviation_id or not description:
                st.warning("Deviation ID와 Description은 필수입니다.")
            else:
                sql = """
                    INSERT INTO deviations
                    (deviation_id, batch_id, description, immediate_action, root_cause, status, created_by, detected_time)
                    VALUES (%s, %s, %s, %s, %s, 'Open', %s, NOW())
                """
                # 🔥 여기 원래 코드에 있던 오타 수정:
                # execute_query(... (deviation_id, batch,args(...)) → 정상 파라미터로 수정
                execute_query(
                    sql,
                    (deviation_id, batch_id, description, immediate_action, root_cause, user["id"]),
                    commit=True,
                )
                st.success("일탈이 생성되었습니다.")
                st.experimental_rerun()


# ==========================================
# 7. CAPA
# ==========================================
def page_capa():
    require_login()
    user = st.session_state["user"]

    st.header("🛠 CAPA")

    tab1, tab2 = st.tabs(["CAPA 목록", "새 CAPA 생성"])

    # LIST
    with tab1:
        rows = execute_query("SELECT * FROM capas ORDER BY id DESC", fetchall=True)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 CAPA가 없습니다.")

    # CREATE
    with tab2:
        capa_id = st.text_input("CAPA ID")
        action_plan = st.text_area("Action Plan")
        corrective_action = st.text_area("Corrective Action")
        preventive_action = st.text_area("Preventive Action")

        if st.button("CAPA 생성"):
            if not capa_id or not action_plan:
                st.warning("CAPA ID와 Action Plan은 필수입니다.")
            else:
                sql = """
                    INSERT INTO capas
                    (capa_id, action_plan, corrective_action, preventive_action, progress, created_by, created_at)
                    VALUES (%s, %s, %s, %s, 'Not Started', %s, NOW())
                """
                execute_query(
                    sql,
                    (capa_id, action_plan, corrective_action, preventive_action, user["id"]),
                    commit=True,
                )
                st.success("CAPA 생성 완료")
                st.experimental_rerun()


# ==========================================
# 8. RISK ASSESSMENT
# ==========================================
def page_risk_assessment():
    require_login()
    user = st.session_state["user"]

    st.header("📌 품질위험관리 (Risk Assessment)")

    tab1, tab2 = st.tabs(["위험 평가 목록", "새 위험평가 생성"])

    with tab1:
        rows = execute_query("SELECT * FROM risk_assessment ORDER BY id DESC", fetchall=True)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 위험평가가 없습니다.")

    with tab2:
        title = st.text_input("Title")
        description = st.text_area("Description")
        impact = st.text_area("Impact")
        risk_level = st.selectbox("Risk Level", ["Low", "Medium", "High"])

        if st.button("위험평가 생성"):
            if not title or not description:
                st.warning("Title과 Description은 필수입니다.")
            else:
                sql = """
                    INSERT INTO risk_assessment
                    (title, description, impact, risk_level, created_by, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """
                execute_query(
                    sql,
                    (title, description, impact, risk_level, user["id"]),
                    commit=True,
                )
                st.success("위험평가가 등록되었습니다.")
                st.experimental_rerun()


# ==========================================
# 9. USER MANAGEMENT (ADMIN ONLY)
# ==========================================
def page_users():
    require_role(["ADMIN"])
    admin = st.session_state["user"]

    st.header("👤 사용자 관리 (ADMIN 전용)")

    tabs = st.tabs(["사용자 목록", "새 사용자 생성"])

    # LIST
    with tabs[0]:
        rows = execute_query("SELECT id, username, role, created_at FROM users ORDER BY id", fetchall=True)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 사용자가 없습니다.")

    # CREATE
    with tabs[1]:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["OPERATOR", "QA", "QC", "ADMIN"])

        if st.button("사용자 생성"):
            if not username or not password:
                st.warning("Username / Password는 필수입니다.")
            else:
                hashed = hash_password(password)
                sql = "INSERT INTO users (username, password_hash, role, created_at) VALUES (%s, %s, %s, NOW())"
                execute_query(sql, (username, hashed, role), commit=True)
                st.success("사용자 생성 완료")
                st.experimental_rerun()


# ==========================================
# 10. MAIN
# ==========================================
def main():
    st.set_page_config(page_title="GMP QMS", layout="wide")

    # 로그인 안 되어 있으면 로그인 화면
    if "user" not in st.session_state:
        login_screen()
        return

    user = st.session_state["user"]

    st.sidebar.title("QMS 메뉴")
    st.sidebar.write(f"👤 {user['username']} ({user['role']})")
    if st.sidebar.button("로그아웃"):
        st.session_state.pop("user")
        st.experimental_rerun()

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
