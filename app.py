# app.py
import streamlit as st
from login import login_form

st.set_page_config(page_title="GMP QMS Demo", layout="wide")

def main():
    st.title("GMP QA e-Workflow Demo")

    if "user" not in st.session_state:
        login_form()
    else:
        user = st.session_state["user"]
        st.success(f"로그인: {user['username']} ({user['role']})")

        if st.button("로그아웃"):
            st.session_state.pop("user")
            st.experimental_rerun()

        st.markdown("---")
        st.write("좌측 페이지 메뉴에서 모듈을 선택해 사용하세요.")

if __name__ == "__main__":
    main()
