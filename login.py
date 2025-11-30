# 로그인
import streamlit as st
from db import execute_query
from utils.security import hash_password, check_password

def get_user_by_username(username: str):
    sql = "SELECT * FROM users WHERE username=%s"
    return execute_query(sql, (username,), fetchone=True)

def create_user(username, password, role="OPERATOR", email=None):
    hashed = hash_password(password)
    sql = "INSERT INTO users (username, password_hash, role, email) VALUES (%s,%s,%s,%s)"
    execute_query(sql, (username, hashed, role, email), commit=True)

def login_form():
    st.subheader("로그인")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = get_user_by_username(username)
        if not user:
            st.error("존재하지 않는 계정입니다.")
            return

        # temp는 최초 관리자 계정용
        if user["password_hash"] == "temp":
            # 임시 계정은 비밀번호 그대로 통과
            ok = (password == "temp")
        else:
            ok = check_password(password, user["password_hash"])

        if ok:
            st.session_state["user"] = {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            }
            st.success("로그인 완료")
            st.experimental_rerun()
        else:
            st.error("비밀번호가 올바르지 않습니다.")

def require_login():
    if "user" not in st.session_state:
        st.warning("이 기능을 사용하려면 로그인이 필요합니다.")
        st.stop()

def require_role(roles):
    require_login()
    if st.session_state["user"]["role"] not in roles:
        st.error("접근 권한이 없습니다.")
        st.stop()
