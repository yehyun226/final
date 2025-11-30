# -*- coding: utf-8 -*-
import os
import streamlit as st
import pymysql
import bcrypt
import pandas as pd
from datetime import datetime, date


# ====================================================
# 0. DB CONNECTION
# ====================================================
def db_conn():
    return pymysql.connect(
        host=os.environ["MYSQL_HOST"],
        user=os.environ["MYSQL_USER"],
        password=os.environ["MYSQL_PASSWORD"],
        database=os.environ["MYSQL_DB"],
        port=int(os.environ["MYSQL_PORT"]),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )


def q(sql, params=None, one=False, all=False, commit=False):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute(sql, params or ())
    result = None

    if one:
        result = cur.fetchone()
    elif all:
        result = cur.fetchall()

    if commit:
        conn.commit()

    cur.close()
    conn.close()
    return result


# ====================================================
# 1. AUTH
# ====================================================
def hash_pw(pw):
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_pw(pw, hashed):
    return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))


def login_screen():
    st.title("🔐 GMP QMS Login")

    username = st.text_input("Username")
    pw = st.text_input("Password", type="password")

    if st.button("로그인"):
        user = q("SELECT * FROM users WHERE username=%s", (username,), one=True)
        if not user:
            st.error("존재하지 않는 사용자입니다.")
            return

        if verify_pw(pw, user["password_hash"]):
            st.session_state["user"] = {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"]
            }
            st.success("로그인 성공")
            st.rerun()
        else:
            st.error("비밀번호가 틀립니다.")


def login_required():
    if "user" not in st.session_state:
        st.warning("로그인이 필요합니다.")
        st.stop()


def role_required(roles):
    login_required()
    if st.session_state["user"]["role"] not in roles:
        st.error("접근 권한 없음.")
        st.stop()


# ====================================================
# 2. AUDIT TRAIL
# ====================================================
def log_action(user_id, action_type, obj_type, obj_id,
               field=None, old=None, new=None):

    sql = """
    INSERT INTO audit_logs
    (user_id, action_type, object_type, object_id, field_name, old_value, new_value)
    VALUES (%s,%s,%s,%s,%s,%s,%s)
    """
    q(sql, (user_id, action_type, obj_type, obj_id, field, old, new), commit=True)


# ====================================================
# 3. CHANGE CONTROL
# ====================================================
def page_change_control():
    login_required()
    user = st.session_state["user"]

    st.subheader("📋 Change Control")

    tab_list, tab_new, tab_status = st.tabs(["목록", "새 변경 생성", "상태 변경"])

    # LIST
    with tab_list:
        rows = q("SELECT * FROM change_controls ORDER BY created_at DESC", all=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    # NEW
    with tab_new:
        title = st.text_input("변경 제목")
        ctype = st.selectbox("변경 유형", ["공정 변경", "설비 변경", "시험법 변경", "원자재 변경"])
        description = st.text_area("변경 상세 내용")
        impact = st.text_input("영향 평가")
        risk_level = st.selectbox("위험 수준", ["Low", "Medium", "High"])

        if st.button("등록"):
            change_id = "CHG-" + datetime.now().strftime("%Y%m%d-%H%M%S")

            sql = """
            INSERT INTO change_controls
            (change_id, title, type, description, impact, risk_level,
             created_by, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,'Draft')
            """

            q(sql, (change_id, title, ctype, description, impact,
                    risk_level, user["id"]), commit=True)

            log_action(user["id"], "CREATE", "CHANGE", change_id, new=title)
            st.success(f"등록 완료! ID: {change_id}")
            st.rerun()

    # STATUS
    with tab_status:
        change_id = st.text_input("Change ID 검색")

        if st.button("조회"):
            row = q("SELECT * FROM change_controls WHERE change_id=%s",
                    (change_id,), one=True)
            if not row:
                st.error("ID 없음")
            else:
                st.session_state["selected_change"] = row

        row = st.session_state.get("selected_change")
        if row:
            st.write(row)
            new_status = st.selectbox(
                "상태 변경",
                ["Draft", "Review", "QA Review", "Approved", "Implemented", "Closed"],
                index=["Draft", "Review", "QA Review", "Approved",
                       "Implemented", "Closed"].index(row["status"])
            )

            if st.button("업데이트"):
                old = row["status"]
                q("""
                UPDATE change_controls
                SET status=%s, updated_at=NOW()
                WHERE id=%s
                """, (new_status, row["id"]), commit=True)

                log_action(user["id"], "STATUS_CHANGE", "CHANGE",
                           row["change_id"], field="status", old=old, new=new_status)

                st.success("상태 수정됨")
                st.rerun()


# ====================================================
# 4. DEVIATION
# ====================================================
def page_deviation():
    login_required()
    user = st.session_state["user"]

    st.subheader("⚠️ Deviation")

    tabs = st.tabs(["일탈 목록", "일탈 등록"])

    with tabs[0]:
        rows = q("SELECT * FROM deviations ORDER BY detected_time DESC", all=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    with tabs[1]:
        deviation_id = "DEV-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        st.text(f"ID 자동 생성: {deviation_id}")

        batch_id = st.text_input("Batch ID")
        description = st.text_area("Deviation 상세 내용")
        immediate_action = st.text_area("즉시 조치")
        preventive_action = st.text_area("예방 조치")
        root_cause = st.text_area("Root Cause")
        risk_eval = st.selectbox("위험 평가", ["Low", "Medium", "High"])

        if st.button("등록"):
            sql = """
            INSERT INTO deviations
            (deviation_id, batch_id, description, detected_time,
             immediate_action, preventive_action, root_cause,
             risk_eval, status, created_by)
            VALUES (%s,%s,%s,NOW(),%s,%s,%s,%s,'Open',%s)
            """

            q(sql, (deviation_id, batch_id, description,
                    immediate_action, preventive_action, root_cause,
                    risk_eval, user["id"]), commit=True)

            log_action(user["id"], "CREATE", "DEVIATION",
                       deviation_id, new=description[:100])

            st.success(f"등록 완료! ID = {deviation_id}")
            st.rerun()


# ====================================================
# 5. CAPA
# ====================================================
def page_capa():
    login_required()
    user = st.session_state["user"]

    st.subheader("🛠 CAPA")

    tab1, tab2 = st.tabs(["CAPA 목록", "CAPA 등록"])

    with tab1:
        rows = q("SELECT * FROM capas ORDER BY id DESC", all=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    with tab2:
        capa_id = "CAPA-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        st.text(f"ID 자동 생성: {capa_id}")

        from_type = st.selectbox("연계 타입", ["DEVIATION", "CHANGE"])
        from_id = st.text_input("연계 Object ID")

        action_plan = st.text_area("Action Plan")
        corrective_action = st.text_area("Corrective Action")
        preventive_action = st.text_area("Preventive Action")
        owner_id = st.number_input("담당자(User ID)", min_value=1)
        due_date = st.date_input("Due Date", date.today())
        progress = st.selectbox("진행 상태", ["Not Started", "In Progress", "Completed"])

        if st.button("등록"):
            q("""
            INSERT INTO capas
            (capa_id, from_type, from_id, action_plan,
             corrective_action, preventive_action,
             owner_id, progress, due_date)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (capa_id, from_type, from_id, action_plan,
                  corrective_action, preventive_action,
                  owner_id, progress, due_date), commit=True)

            log_action(user["id"], "CREATE", "CAPA",
                       capa_id, new=action_plan[:80])

            st.success("CAPA 등록 완료!")
            st.rerun()


# ====================================================
# 6. RISK ASSESSMENT
# ====================================================
def page_risk():
    login_required()
    user = st.session_state["user"]

    st.subheader("📊 Risk Assessment")

    tab1, tab2 = st.tabs(["Risk 목록", "Risk 생성"])

    with tab1:
        rows = q("SELECT * FROM risk_assessment ORDER BY created_at DESC", all=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    with tab2:
        obj_type = st.selectbox("Object Type", ["CHANGE", "DEVIATION", "CAPA"])
        obj_id = st.text_input("Object ID")

        sev = st.slider("Severity", 1, 10, 5)
        occ = st.slider("Occurrence", 1, 10, 5)
        det = st.slider("Detection", 1, 10, 5)

        if st.button("저장"):
            risk_score = sev * occ * det

            q("""
            INSERT INTO risk_assessment
            (object_type, object_id, severity, occurrence,
             detection, risk_score, created_by)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (obj_type, obj_id, sev, occ, det, risk_score, user["id"]),
              commit=True)

            log_action(user["id"], "CREATE", "RISK",
                       f"{obj_type}:{obj_id}", new=f"RPN={risk_score}")

            st.success(f"저장 완료! RPN = {risk_score}")
            st.rerun()


# ====================================================
# 7. ATTACHMENTS (미니 버전)
# ====================================================
def page_attachments():
    st.subheader("📎 Attachments")
    st.info("첨부파일 기능은 원하면 바로 구현해드립니다.")


# ====================================================
# 8. AUDIT TRAIL
# ====================================================
def page_audit():
    login_required()

    st.subheader("🧾 Audit Trail (최근 300개)")

    rows = q("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 300", all=True)
    st.dataframe(pd.DataFrame(rows), use_container_width=True)


# ====================================================
# 9. DASHBOARD
# ====================================================
def page_dashboard():
    st.subheader("📊 Dashboard 요약")

    cc = q("SELECT status, COUNT(*) AS cnt FROM change_controls GROUP BY status", all=True)
    dv = q("SELECT status, COUNT(*) AS cnt FROM deviations GROUP BY status", all=True)
    cp = q("SELECT progress, COUNT(*) AS cnt FROM capas GROUP BY progress", all=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.write("### Change Control")
        st.dataframe(pd.DataFrame(cc))
    with col2:
        st.write("### Deviation")
        st.dataframe(pd.DataFrame(dv))
    with col3:
        st.write("### CAPA")
        st.dataframe(pd.DataFrame(cp))


# ====================================================
# 10. USER MANAGEMENT (ADMIN)
# ====================================================
def page_users():
    role_required(["ADMIN"])

    st.subheader("👤 User Management")

    tab1, tab2 = st.tabs(["목록", "사용자 생성"])

    with tab1:
        rows = q("SELECT id, username, role, created_at FROM users ORDER BY id", all=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    with tab2:
        username = st.text_input("Username")
        pw = st.text_input("초기 Password", type="password")
        role = st.selectbox("Role", ["OPERATOR", "QA", "QC", "ADMIN"])

        if st.button("생성"):
            hashed = hash_pw(pw)
            q("INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)",
              (username, hashed, role), commit=True)
            st.success("사용자 생성 완료!")
            st.rerun()


# ====================================================
# 11. MAIN ROUTER (사이드바 + 탭)
# ====================================================
def main():
    st.set_page_config(page_title="GMP QMS", layout="wide")

    if "user" not in st.session_state:
        login_screen()
        return

    user = st.session_state["user"]

    st.sidebar.title("GMP QMS")
    st.sidebar.success(f"{user['username']} ({user['role']})")

    if st.sidebar.button("로그아웃"):
        st.session_state.pop("user")
        st.rerun()

    # ---------------------------
    # 사이드바
    # ---------------------------
    menu = st.sidebar.radio(
        "Menu",
        [
            "변경관리 (Change Control)",
            "일탈관리 (Deviation)",
            "CAPA",
            "품질위험관리 (QRM)",
            "────────────",
            "Dashboard",
            "User Management (Admin)"
        ]
    )

    # ---------------------------
    # ROUTING (대분류 → 탭)
    # ---------------------------

    if menu == "변경관리 (Change Control)":
        tabs = st.tabs(["Change Control", "Attachments", "Audit Trail", "Dashboard"])

        with tabs[0]:
            page_change_control()
        with tabs[1]:
            page_attachments()
        with tabs[2]:
            page_audit()
        with tabs[3]:
            page_dashboard()

    elif menu == "일탈관리 (Deviation)":
        tabs = st.tabs(["Deviation", "CAPA", "Audit Trail"])

        with tabs[0]:
            page_deviation()
        with tabs[1]:
            page_capa()
        with tabs[2]:
            page_audit()

    elif menu == "CAPA":
        tabs = st.tabs(["CAPA", "Dashboard", "Attachments"])

        with tabs[0]:
            page_capa()
        with tabs[1]:
            page_dashboard()
        with tabs[2]:
            page_attachments()

    elif menu == "품질위험관리 (QRM)":
        tabs = st.tabs(["Risk Assessment", "Audit Trail"])

        with tabs[0]:
            page_risk()
        with tabs[1]:
            page_audit()

    elif menu == "Dashboard":
        page_dashboard()

    elif menu == "User Management (Admin)":
        page_users()


if __name__ == "__main__":
    main()
