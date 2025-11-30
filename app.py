# -*- coding: utf-8 -*-
import os
from datetime import datetime, date

import streamlit as st
import pymysql
import pandas as pd
import bcrypt


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
# 1. ROLE PERMISSIONS
# ====================================================
ROLE_PERMISSIONS = {
    "OPERATOR": {
        "change_control": ["create", "view"],
        "deviations": ["create", "view"],
        "capa": ["create", "view"],
        "risk": ["view"],
        "attachments": ["upload_own", "view_own"],
        "user_management": [],
        "audit_logs": []
    },

    "QA": {
        "change_control": ["create", "edit", "review", "approve", "view"],
        "deviations": ["create", "edit", "review", "approve", "view"],
        "capa": ["create", "edit", "review", "approve", "view"],
        "risk": ["create", "edit", "approve", "view"],
        "attachments": ["upload", "view"],
        "user_management": [],
        "audit_logs": ["view"]
    },

    "QC": {
        "change_control": ["view"],
        "deviations": ["create", "edit_partial", "view"],
        "capa": ["create", "edit_partial", "view"],
        "risk": ["view"],
        "attachments": ["upload_own", "view_own"],
        "user_management": [],
        "audit_logs": []
    },

    "ADMIN": {
        "change_control": ["create", "edit", "delete", "force_approve", "view"],
        "deviations": ["create", "edit", "delete", "force_approve", "view"],
        "capa": ["create", "edit", "delete", "force_approve", "view"],
        "risk": ["create", "edit", "delete", "approve", "view"],
        "attachments": ["upload", "delete", "view_all"],
        "user_management": ["create", "edit", "delete", "assign_roles"],
        "audit_logs": ["view_all"]
    }
}


# ====================================================
# 2. PERMISSION CHECK
# ====================================================
def require_permission(module, action):
    user = st.session_state.get("user")
    if not user:
        st.error("로그인이 필요합니다.")
        st.stop()

    role = user["role"]
    allowed = ROLE_PERMISSIONS.get(role, {}).get(module, [])

    if action not in allowed:
        st.error("⚠️ 접근 권한이 없습니다.")
        st.stop()


# ====================================================
# 3. PASSWORD / AUTH
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
            st.error("비밀번호가 올바르지 않습니다.")


def login_required():
    if "user" not in st.session_state:
        st.warning("로그인이 필요합니다.")
        st.stop()


# ====================================================
# 4. AUDIT TRAIL LOG
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
# 5. CHANGE CONTROL PAGE
# ====================================================
def page_change_control():
    login_required()
    st.header("📋 Change Control")

    tab_list, tab_new, tab_status = st.tabs(["목록", "새 변경 생성", "상태 변경"])

    # ---------------- LIST ----------------
    with tab_list:
        require_permission("change_control", "view")
        rows = q("SELECT * FROM change_controls ORDER BY created_at DESC", all=True)
        st.dataframe(pd.DataFrame(rows) if rows else pd.DataFrame())

    # ---------------- NEW ----------------
    with tab_new:
        require_permission("change_control", "create")

        title = st.text_input("변경 제목")
        ctype = st.selectbox("변경 유형", ["공정 변경", "설비 변경", "시험법 변경", "원자재 변경"])
        description = st.text_area("Detail Description")
        impact = st.text_input("영향받는 공정/설비/제품")
        risk_level = st.selectbox("위험도", ["Low", "Medium", "High"])

        if st.button("생성"):
            change_id = "CHG-" + datetime.now().strftime("%Y%m%d-%H%M%S")

            sql = """
            INSERT INTO change_controls
            (change_id, title, type, description, impact, risk_level, created_by, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """

            q(sql, (change_id, title, ctype, description,
                    impact, risk_level, st.session_state["user"]["id"], "Draft"),
              commit=True)

            log_action(st.session_state["user"]["id"], "CREATE", "CHANGE", change_id, new=title)
            st.success(f"등록 완료! (ID={change_id})")
            st.rerun()

    # ---------------- STATUS CHANGE ----------------
    with tab_status:
        require_permission("change_control", "edit")

        cid = st.text_input("Change ID 입력")

        if st.button("불러오기"):
            row = q("SELECT * FROM change_controls WHERE change_id=%s", (cid,), one=True)
            st.session_state["selected_change"] = row

        row = st.session_state.get("selected_change")
        if row:
            st.write(row)

            new_status = st.selectbox(
                "새 상태",
                ["Draft", "Review", "QA Review", "Approved", "Implemented", "Closed"],
                index=["Draft", "Review", "QA Review", "Approved", "Implemented", "Closed"].index(row["status"])
            )

            if st.button("상태 업데이트"):
                old = row["status"]

                q("UPDATE change_controls SET status=%s, updated_at=NOW() WHERE id=%s",
                  (new_status, row["id"]), commit=True)

                log_action(
                    st.session_state["user"]["id"], "STATUS_CHANGE",
                    "CHANGE", row["change_id"], field="status", old=old, new=new_status
                )

                st.success("상태 변경 완료")
                st.rerun()


# ====================================================
# 6. DEVIATION
# ====================================================
def page_deviation():
    login_required()
    st.header("⚠️ Deviation")

    tab_list, tab_new = st.tabs(["목록", "새 일탈 등록"])

    # LIST
    with tab_list:
        require_permission("deviations", "view")
        rows = q("SELECT * FROM deviations ORDER BY detected_time DESC", all=True)
        st.dataframe(pd.DataFrame(rows) if rows else pd.DataFrame())

    # CREATE
    with tab_new:
        require_permission("deviations", "create")

        deviation_id = "DEV-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        st.text(f"자동 생성 ID: {deviation_id}")

        batch_id = st.text_input("Batch ID")
        description = st.text_area("Deviation 상세 내용")
        immediate_action = st.text_area("즉시 조치")
        preventive_action = st.text_area("예방 조치")
        root_cause = st.text_area("Root Cause")
        risk_eval = st.selectbox("Risk 평가", ["Low", "Medium", "High"])

        if st.button("Deviation 등록"):
            sql = """
            INSERT INTO deviations
            (deviation_id, batch_id, description, detected_time,
             immediate_action, preventive_action, root_cause,
             risk_eval, status, created_by)
            VALUES (%s,%s,%s,NOW(),%s,%s,%s,%s,'Open',%s)
            """

            q(sql, (deviation_id, batch_id, description,
                    immediate_action, preventive_action,
                    root_cause, risk_eval,
                    st.session_state["user"]["id"]),
              commit=True)

            log_action(st.session_state["user"]["id"],
                       "CREATE", "DEVIATION", deviation_id,
                       new=description[:100])

            st.success(f"등록 완료! (ID={deviation_id})")
            st.rerun()


# ====================================================
# 7. CAPA
# ====================================================
def page_capa():
    login_required()
    st.header("🛠 CAPA")

    tab_list, tab_new = st.tabs(["목록", "CAPA 생성"])

    with tab_list:
        require_permission("capa", "view")
        rows = q("SELECT * FROM capas ORDER BY id DESC", all=True)
        st.dataframe(pd.DataFrame(rows) if rows else pd.DataFrame())

    with tab_new:
        require_permission("capa", "create")

        capa_id = "CAPA-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        st.text(f"자동 생성 CAPA ID: {capa_id}")

        from_type = st.selectbox("연계 타입", ["DEVIATION", "CHANGE"])
        from_id = st.text_input("연계 Object ID")

        action_plan = st.text_area("Action Plan")
        corrective_action = st.text_area("Corrective Action")
        preventive_action = st.text_area("Preventive Action")
        owner_id = st.number_input("담당자 User ID", min_value=1)
        due_date = st.date_input("Due Date", date.today())
        progress = st.selectbox("진행 상태", ["Not Started", "In Progress", "Completed"])

        if st.button("CAPA 등록"):

            sql = """
            INSERT INTO capas
            (capa_id, from_type, from_id, action_plan,
             corrective_action, preventive_action,
             owner_id, progress, due_date)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """

            q(sql, (capa_id, from_type, from_id, action_plan,
                    corrective_action, preventive_action,
                    owner_id, progress, due_date),
              commit=True)

            log_action(st.session_state["user"]["id"], "CREATE", "CAPA",
                       capa_id, new=action_plan[:80])

            st.success(f"CAPA 등록 완료! (ID={capa_id})")
            st.rerun()


# ====================================================
# 8. RISK
# ====================================================
def page_risk():
    login_required()
    st.header("📊 Risk Assessment")

    tab_list, tab_new = st.tabs(["목록", "Risk 평가 생성"])

    with tab_list:
        require_permission("risk", "view")
        rows = q("SELECT * FROM risk_assessment ORDER BY created_at DESC", all=True)
        st.dataframe(pd.DataFrame(rows) if rows else pd.DataFrame())

    with tab_new:
        require_permission("risk", "create")

        object_type = st.selectbox("Object Type", ["CHANGE", "DEVIATION", "CAPA"])
        object_id = st.text_input("Object ID")

        sev = st.slider("Severity", 1, 10, 5)
        occ = st.slider("Occurrence", 1, 10, 5)
        det = st.slider("Detection", 1, 10, 5)

        if st.button("Risk 평가 저장"):
            risk_score = sev * occ * det

            sql = """
            INSERT INTO risk_assessment
            (object_type, object_id, severity, occurrence,
             detection, risk_score, created_by)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """

            q(sql, (object_type, object_id, sev, occ, det,
                    risk_score, st.session_state["user"]["id"]),
              commit=True)

            log_action(
                st.session_state["user"]["id"], "CREATE",
                "RISK", f"{object_type}:{object_id}",
                new=f"RPN={risk_score}"
            )

            st.success(f"저장 완료! RPN = {risk_score}")
            st.rerun()


# ====================================================
# 9. USER MANAGEMENT (ADMIN)
# ====================================================
def page_users():
    login_required()
    require_permission("user_management", "create")

    st.header("👤 사용자 관리 (Admin)")

    tab_list, tab_new = st.tabs(["목록", "새 사용자 생성"])

    with tab_list:
        rows = q("SELECT id, username, role, created_at, email FROM users ORDER BY id", all=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    with tab_new:
        username = st.text_input("Username")
        email = st.text_input("Email")
        pw = st.text_input("초기 Password", type="password")
        role = st.selectbox("Role", ["OPERATOR", "QA", "QC", "ADMIN"])

        if st.button("사용자 생성"):
            hashed = hash_pw(pw)

            q("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s,%s,%s,%s)
                """,
              (username, email, hashed, role),
              commit=True)

            st.success(f"사용자 {username} 생성 완료!")
            st.rerun()


# ====================================================
# 10. AUDIT TRAIL
# ====================================================
def page_audit():
    login_required()
    require_permission("audit_logs", "view")

    st.header("🧾 Audit Trail")

    rows = q("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 300", all=True)

    st.dataframe(pd.DataFrame(rows) if rows else pd.DataFrame())


# ====================================================
# 11. MAIN
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

    menu = st.sidebar.radio(
        "Menu",
        [
            "Dashboard",
            "Change Control",
            "Deviation",
            "CAPA",
            "Risk Assessment",
            "Audit Trail",
            "User Management (Admin)"
        ]
    )

    if menu == "Dashboard":
        st.header("📊 Dashboard Summary")
        st.write("변경관리, 일탈, CAPA, 위험평가 통계 요약")

        cc = q("SELECT status, COUNT(*) AS cnt FROM change_controls GROUP BY status", all=True)
        dv = q("SELECT status, COUNT(*) AS cnt FROM deviations GROUP BY status", all=True)
        cp = q("SELECT progress, COUNT(*) AS cnt FROM capas GROUP BY progress", all=True)

        col1, col2, col3 = st.columns(3)

        with col1:
            st.subheader("Change")
            if cc:
                st.dataframe(pd.DataFrame(cc))

        with col2:
            st.subheader("Deviation")
            if dv:
                st.dataframe(pd.DataFrame(dv))

        with col3:
            st.subheader("CAPA")
            if cp:
                st.dataframe(pd.DataFrame(cp))

    elif menu == "Change Control":
        page_change_control()

    elif menu == "Deviation":
        page_deviation()

    elif menu == "CAPA":
        page_capa()

    elif menu == "Risk Assessment":
        page_risk()

    elif menu == "Audit Trail":
        page_audit()

    elif menu == "User Management (Admin)":
        page_users()


if __name__ == "__main__":
    main()
