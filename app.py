# -*- coding: utf-8 -*-
import os
from datetime import datetime, date

import streamlit as st
import pymysql
import pandas as pd
import bcrypt
import uuid  # ID 자동 생성용
from st_aggrid import AgGrid, GridOptionsBuilder

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
        autocommit=True,
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
        "audit_logs": [],
    },
    "QA": {
        "change_control": ["create", "edit", "review", "approve", "view"],
        "deviations": ["create", "edit", "review", "approve", "view"],
        "capa": ["create", "edit", "review", "approve", "view"],
        "risk": ["create", "edit", "approve", "view"],
        "attachments": ["upload", "view"],
        "user_management": [],
        "audit_logs": ["view"],
    },
    "QC": {
        "change_control": ["view"],
        "deviations": ["create", "edit_partial", "view"],
        "capa": ["create", "edit_partial", "view"],
        "risk": ["view"],
        "attachments": ["upload_own", "view_own"],
        "user_management": [],
        "audit_logs": [],
    },
    "ADMIN": {
        "change_control": ["create", "edit", "delete", "force_approve", "view"],
        "deviations": ["create", "edit", "delete", "force_approve", "view"],
        "capa": ["create", "edit", "delete", "force_approve", "view"],
        "risk": ["create", "edit", "delete", "approve", "view"],
        "attachments": ["upload", "delete", "view_all"],
        "user_management": ["create", "edit", "delete", "assign_roles"],
        "audit_logs": ["view_all"],
    },
}


# ====================================================
# 2. AUTH / LOGIN
# ====================================================
def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_pw(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))


def login_required():
    if "user" not in st.session_state:
        st.warning("로그인이 필요합니다.")
        st.stop()


def require_permission(module: str, action: str):
    user = st.session_state.get("user")
    if not user:
        st.error("로그인이 필요합니다.")
        st.stop()

    role = user["role"]
    allowed = ROLE_PERMISSIONS.get(role, {}).get(module, [])

    if action == "view" and "view_all" in allowed:
        return

    if action not in allowed:
        st.error("⚠️ 접근 권한이 없습니다.")
        st.stop()


def login_screen():
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.markdown("<h2>🔐 GMP QMS Login</h2>", unsafe_allow_html=True)

    username = st.text_input("Username")
    pw = st.text_input("Password", type="password")

    if st.button("로그인"):
        user = q("SELECT * FROM users WHERE username=%s", (username,), one=True)
        if not user:
            st.error("존재하지 않는 사용자입니다.")
            return

        if not user.get("password_hash"):
            st.error("비밀번호가 설정되지 않은 계정입니다.")
            return

        if verify_pw(pw, user["password_hash"]):
            st.session_state["user"] = {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            }
            st.success("로그인 성공")
            st.rerun()
        else:
            st.error("비밀번호가 올바르지 않습니다.")

    st.markdown("</div>", unsafe_allow_html=True)


# ====================================================
# 3. AUDIT LOG
# ====================================================
def log_action(user_id, action_type, obj_type, obj_id,
               field_name=None, old_value=None, new_value=None):
    sql = """
    INSERT INTO audit_logs
    (user_id, action_type, object_type, object_id, field_name, old_value, new_value)
    VALUES (%s,%s,%s,%s,%s,%s,%s)
    """
    q(sql, (user_id, action_type, obj_type, obj_id,
            field_name, old_value, new_value), commit=True)


# ====================================================
# 4. ID GENERATORS
# ====================================================
def generate_change_id():
    return "CHG-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def generate_capa_id():
    return "CAPA-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def generate_deviation_id():
    return "DEV-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def generate_risk_id():
    return "RISK-" + datetime.now().strftime("%Y%m%d-%H%M%S")


# ====================================================
# 5. CHANGE CONTROL
# (기존 유지, 변화 없음)
# ====================================================
def page_change_control():
    login_required()
    user = st.session_state["user"]

    st.markdown(
        """
        <div class="header-box">
            <h2>📋 Change Control</h2>
            <p>공정·설비·시험법·원자재 등의 변경을 등록하고 상태를 추적합니다.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_list, tab_new, tab_status = st.tabs(["목록", "새 변경 생성", "상태 변경"])

    # ---------- LIST ----------
    with tab_list:
        require_permission("change_control", "view")
        rows = q("SELECT * FROM change_controls ORDER BY created_at DESC", all=True)
        if rows:
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            df = pd.DataFrame(rows)
            st.data_editor(df, use_container_width=True, height=400)
        else:
            st.info("등록된 Change Control이 없습니다.")
    
    
            


    # ---------- NEW ----------
    with tab_new:
        require_permission("change_control", "create")

        if "new_change_id" not in st.session_state:
            st.session_state["new_change_id"] = generate_change_id()
        change_id = st.session_state["new_change_id"]

        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.text(f"자동 생성 Change ID: {change_id}")

        title = st.text_input("변경 제목")
        ctype = st.selectbox("변경 유형", ["공정 변경", "설비 변경", "시험법 변경", "원자재 변경"])
        description = st.text_area("Detail Description")
        impact = st.text_input("영향받는 공정/설비/제품")
        risk_level = st.selectbox("위험도", ["Low", "Medium", "High"])

        if st.button("생성"):
            if not title or not description:
                st.warning("제목과 설명은 필수입니다.")
            else:
                sql = """
                INSERT INTO change_controls
                (change_id, title, type, description, impact, risk_level,
                 created_by, status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """
                params = (
                    change_id, title, ctype, description,
                    impact, risk_level, user["id"], "Draft"
                )

                q(sql, params, commit=True)

                log_action(user["id"], "CREATE", "CHANGE", change_id, new_value=title)

                st.session_state.pop("new_change_id", None)

                st.success(f"등록 완료! (ID = {change_id})")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- STATUS CHANGE ----------
    with tab_status:
        require_permission("change_control", "edit")

        st.markdown("<div class='card'>", unsafe_allow_html=True)
        cid = st.text_input("Change ID 입력")

        if st.button("불러오기"):
            row = q("SELECT * FROM change_controls WHERE change_id=%s", (cid,), one=True)
            if not row:
                st.error("해당 ID 없음")
            else:
                st.session_state["selected_change"] = row

        row = st.session_state.get("selected_change")
        if row:
            st.write("선택된 Change:", row)

            status_options = ["Draft", "Review", "QA Review", "Approved", "Implemented", "Closed"]
            cur = row.get("status") or "Draft"
            idx = status_options.index(cur) if cur in status_options else 0

            new_status = st.selectbox("새 상태", status_options, index=idx)

            if st.button("상태 업데이트"):
                q(
                    "UPDATE change_controls SET status=%s, updated_at=NOW() WHERE id=%s",
                    (new_status, row["id"]),
                    commit=True,
                )

                log_action(
                    user["id"], "STATUS_CHANGE", "CHANGE",
                    row["change_id"],
                    "status", cur, new_status
                )

                st.success("상태 변경 완료")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# ====================================================
# 6. DEVIATION (Batch ID 삭제 + Title 추가)
# ====================================================
def page_deviation():
    login_required()
    user = st.session_state["user"]

    st.markdown(
        """
        <div class="header-box">
            <h2>⚠️ Deviation</h2>
            <p>일탈 발생 시 등록하고, 조사·조치·종결까지 이력을 관리합니다.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_list, tab_new, tab_status = st.tabs(["목록", "새 일탈 등록", "상태 변경"])

    # ---------- LIST ----------
    with tab_list:
        require_permission("deviations", "view")
        rows = q("SELECT * FROM deviations ORDER BY detected_time DESC", all=True)
        if rows:
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("등록된 Deviation이 없습니다.")

    # ---------- NEW ----------
    with tab_new:
        require_permission("deviations", "create")

        deviation_id = generate_deviation_id()
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.text(f"자동 생성 Deviation ID: {deviation_id}")

        title = st.text_input("Deviation 제목", placeholder="예: 중량 이탈 발생")
        description = st.text_area("Deviation 상세 내용")
        immediate_action = st.text_area("즉시 조치")
        preventive_action = st.text_area("예방 조치")
        root_cause = st.text_area("Root Cause")
        risk_eval = st.selectbox("Risk 평가", ["Low", "Medium", "High"])

        if st.button("Deviation 등록"):
            if not title or not description:
                st.warning("제목과 상세 내용은 필수입니다.")
            else:
                sql = """
                INSERT INTO deviations
                (deviation_id, title, description, detected_time,
                 immediate_action, preventive_action, root_cause,
                 risk_eval, status, created_by)
                VALUES (%s,%s,%s,NOW(),%s,%s,%s,%s,'Open',%s)
                """

                params = (
                    deviation_id, title, description,
                    immediate_action, preventive_action,
                    root_cause, risk_eval, user["id"]
                )

                q(sql, params, commit=True)

                log_action(
                    user["id"], "CREATE", "DEVIATION",
                    deviation_id, new_value=title
                )

                st.success(f"Deviation 등록 완료! (ID = {deviation_id})")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- STATUS CHANGE ----------
    with tab_status:
        require_permission("deviations", "edit")

        st.markdown("<div class='card'>", unsafe_allow_html=True)
        dev_id_input = st.text_input("Deviation ID 입력")

        if st.button("Deviation 불러오기"):
            row = q("SELECT * FROM deviations WHERE deviation_id=%s",
                    (dev_id_input,), one=True)
            if not row:
                st.error("해당 ID의 Deviation 없음")
            else:
                st.session_state["selected_deviation"] = row

        row = st.session_state.get("selected_deviation")
        if row:
            st.write("선택된 Deviation:", row)

            status_options = ["Open", "Investigation", "QA Review", "Approved", "Closed"]
            cur = row.get("status") or "Open"
            idx = status_options.index(cur) if cur in status_options else 0

            new_status = st.selectbox("새 상태", status_options, index=idx)

            if st.button("Deviation 상태 저장"):
                q(
                    """
                    UPDATE deviations
                       SET status=%s,
                           updated_by=%s,
                           updated_at=NOW()
                     WHERE id=%s
                    """,
                    (new_status, user["id"], row["id"]),
                    commit=True,
                )

                log_action(
                    user["id"],
                    "STATUS_CHANGE",
                    "DEVIATION",
                    row["deviation_id"],
                    "status", cur, new_status
                )

                st.success("Deviation 상태 변경 완료")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# ====================================================
# 7. CAPA (연계 ID 삭제 + Title 추가)
# ====================================================
def page_capa():
    login_required()
    user = st.session_state["user"]

    st.markdown(
        """
        <div class="header-box">
            <h2>🛠 CAPA</h2>
            <p>일탈·변경 등의 원인을 기반으로 시정·예방조치를 계획하고 추적합니다.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_list, tab_new, tab_status = st.tabs(["목록", "CAPA 생성", "상태 변경"])

    # ---------- LIST ----------
    with tab_list:
        require_permission("capa", "view")
        rows = q("SELECT * FROM capas ORDER BY id DESC", all=True)
        if rows:
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("등록된 CAPA가 없습니다.")

    # ---------- NEW ----------
    with tab_new:
        require_permission("capa", "create")

        capa_id = generate_capa_id()
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.text(f"자동 생성 CAPA ID: {capa_id}")

        capa_title = st.text_input("CAPA 제목", placeholder="예: 공정 오염 가능성 예방 조치")

        from_type = st.selectbox("연계 타입", ["DEVIATION", "CHANGE"])
        action_plan = st.text_area("Action Plan")
        corrective_action = st.text_area("Corrective Action")
        preventive_action = st.text_area("Preventive Action")

        owner_id = st.number_input("담당자 User ID", min_value=1)
        due_date = st.date_input("Due Date", date.today())
        progress = st.selectbox("진행 상태", ["Not Started", "In Progress", "Completed"])

        if st.button("CAPA 등록"):
            if not capa_title or not action_plan:
                st.warning("제목과 Action Plan은 필수입니다.")
            else:
                sql = """
                INSERT INTO capas
                (capa_id, title, from_type, action_plan,
                 corrective_action, preventive_action,
                 owner_id, progress, due_date)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """

                params = (
                    capa_id, capa_title, from_type,
                    action_plan, corrective_action, preventive_action,
                    owner_id, progress, due_date
                )

                q(sql, params, commit=True)

                log_action(
                    user["id"], "CREATE", "CAPA",
                    capa_id, new_value=capa_title
                )

                st.success(f"CAPA 등록 완료! (ID = {capa_id})")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- STATUS CHANGE ----------
    with tab_status:
        require_permission("capa", "edit")

        st.markdown("<div class='card'>", unsafe_allow_html=True)
        capa_id_input = st.text_input("CAPA ID 입력")

        if st.button("CAPA 불러오기"):
            row = q("SELECT * FROM capas WHERE capa_id=%s",
                    (capa_id_input,), one=True)
            if not row:
                st.error("해당 CAPA 없음")
            else:
                st.session_state["selected_capa"] = row

        row = st.session_state.get("selected_capa")
        if row:
            st.write("선택된 CAPA:", row)

            progress_options = ["Not Started", "In Progress", "Completed", "Closed"]
            cur = row.get("progress") or "Not Started"
            idx = progress_options.index(cur) if cur in progress_options else 0

            new_progress = st.selectbox("새 진행 상태", progress_options, index=idx)

            if st.button("CAPA 진행 상태 저장"):
                q(
                    """
                    UPDATE capas
                       SET progress=%s,
                           updated_by=%s,
                           updated_at=NOW()
                     WHERE id=%s
                    """,
                    (new_progress, user["id"], row["id"]),
                    commit=True,
                )

                log_action(
                    user["id"],
                    "STATUS_CHANGE",
                    "CAPA",
                    row["capa_id"],
                    "progress", cur, new_progress
                )

                st.success("CAPA 상태 변경 완료")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# ====================================================
# 8. RISK ASSESSMENT (Object ID 삭제 + Title 추가)
# ====================================================
def page_risk():
    login_required()
    user = st.session_state["user"]

    st.markdown(
        """
        <div class="header-box">
            <h2>📊 Risk Assessment (RPN)</h2>
            <p>변경·일탈·CAPA 건에 대한 Risk Priority Number를 산정합니다.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_list, tab_new, tab_status = st.tabs(["목록", "Risk 평가 생성", "상태 변경"])

    # ---------- LIST ----------
    with tab_list:
        require_permission("risk", "view")
        rows = q("SELECT * FROM risk_assessment ORDER BY created_at DESC", all=True)
        if rows:
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("등록된 Risk 평가가 없습니다.")

    # ---------- NEW ----------
    with tab_new:
        require_permission("risk", "create")

        if "new_risk_id" not in st.session_state:
            st.session_state["new_risk_id"] = generate_risk_id()
        risk_id = st.session_state["new_risk_id"]

        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.text(f"자동 생성 Risk ID: {risk_id}")

        risk_title = st.text_input("Risk Assessment 제목", placeholder="예: 작업자 실수 가능성 증가에 대한 RPN 평가")
        object_type = st.selectbox("Object Type", ["CHANGE", "DEVIATION", "CAPA"])

        sev = st.slider("Severity", 1, 10, 5)
        occ = st.slider("Occurrence", 1, 10, 5)
        det = st.slider("Detection", 1, 10, 5)

        if st.button("Risk 평가 저장"):
            risk_score = sev * occ * det

            sql = """
            INSERT INTO risk_assessment
            (risk_id, title, object_type, severity, occurrence,
             detection, risk_score, status, created_by)
            VALUES (%s,%s,%s,%s,%s,%s,%s,'Draft',%s)
            """

            q(
                sql,
                (risk_id, risk_title, object_type, sev, occ, det, risk_score, user["id"]),
                commit=True,
            )

            log_action(
                user["id"], "CREATE", "RISK", risk_id,
                new_value=f"{risk_title} (RPN={risk_score})"
            )

            st.session_state.pop("new_risk_id", None)

            st.success(f"저장 완료! (Risk ID = {risk_id}, RPN = {risk_score})")
            st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- STATUS CHANGE ----------
    with tab_status:
        require_permission("risk", "edit")

        st.markdown("<div class='card'>", unsafe_allow_html=True)
        rid_input = st.text_input("Risk ID 입력")

        if st.button("Risk 평가 불러오기"):
            row = q("SELECT * FROM risk_assessment WHERE risk_id=%s",
                    (rid_input,), one=True)
            if not row:
                st.error("해당 ID 없음")
            else:
                st.session_state["selected_risk"] = row

        row = st.session_state.get("selected_risk")
        if row:
            st.write("선택된 Risk 평가:", row)

            status_options = ["Draft", "Reviewed", "Approved", "Closed"]
            cur = row.get("status") or "Draft"
            idx = status_options.index(cur) if cur in status_options else 0

            new_status = st.selectbox("새 상태", status_options, index=idx)

            if st.button("Risk 상태 저장"):
                q(
                    "UPDATE risk_assessment SET status=%s WHERE id=%s",
                    (new_status, row["id"]),
                    commit=True,
                )

                log_action(
                    user["id"],
                    "STATUS_CHANGE",
                    "RISK",
                    row["risk_id"],
                    "status", cur, new_status
                )

                st.success("Risk 상태 변경 완료")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# ====================================================
# 9. USER MANAGEMENT (Admin)
# ====================================================
def page_users():
    login_required()
    require_permission("user_management", "create")

    admin = st.session_state["user"]

    st.markdown(
        """
        <div class="header-box">
            <h2>👤 사용자 관리 (Admin)</h2>
            <p>계정 생성, 권한(Role) 부여 등을 관리합니다.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_list, tab_new = st.tabs(["사용자 목록", "새 사용자 생성"])

    with tab_list:
        rows = q("SELECT id, username, role, email, created_at FROM users ORDER BY id", all=True)
        if rows:
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("등록된 사용자가 없습니다.")

    with tab_new:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        username = st.text_input("Username")
        email = st.text_input("Email")
        pw = st.text_input("초기 Password", type="password")
        role = st.selectbox("Role", ["OPERATOR", "QA", "QC", "ADMIN"])

        if st.button("사용자 생성"):
            if not username or not pw:
                st.warning("Username / Password는 필수입니다.")
            else:
                hashed = hash_pw(pw)
                q(
                    "INSERT INTO users (username, password_hash, role, email) VALUES (%s,%s,%s,%s)",
                    (username, hashed, role, email),
                    commit=True,
                )

                log_action(
                    admin["id"],
                    "CREATE_USER",
                    "USER",
                    username,
                    new_value=f"role={role}, email={email}",
                )

                st.success("사용자 생성 완료!")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# ====================================================
# 10. AUDIT TRAIL
# ====================================================
def page_audit():
    login_required()
    require_permission("audit_logs", "view")

    st.markdown(
        """
        <div class="header-box">
            <h2>🧾 Audit Trail</h2>
            <p>모든 주요 변경 및 상태 변경 이력을 감사 용도로 조회합니다.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    rows = q("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 300", all=True)

    if rows:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("표시할 Audit 로그가 없습니다.")


# ====================================================
# 11. DASHBOARD (그대로 유지)
# ====================================================
def page_dashboard():
    login_required()

    st.markdown(
        """
        <div class="header-box">
            <h2>📊 Dashboard Summary</h2>
            <p>Change / Deviation / CAPA 현황을 한 눈에 확인하는 요약 화면입니다.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cc = q("SELECT status, COUNT(*) AS cnt FROM change_controls GROUP BY status", all=True)
    dv = q("SELECT status, COUNT(*) AS cnt FROM deviations GROUP BY status", all=True)
    cp = q("SELECT progress, COUNT(*) AS cnt FROM capas GROUP BY progress", all=True)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.subheader("Change Status")
        if cc:
            st.dataframe(pd.DataFrame(cc), use_container_width=True)
        else:
            st.write("데이터 없음")
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.subheader("Deviation Status")
        if dv:
            st.dataframe(pd.DataFrame(dv), use_container_width=True)
        else:
            st.write("데이터 없음")
        st.markdown("</div>", unsafe_allow_html=True)

    with col3:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.subheader("CAPA Progress")
        if cp:
            st.dataframe(pd.DataFrame(cp), use_container_width=True)
        else:
            st.write("데이터 없음")
        st.markdown("</div>", unsafe_allow_html=True)


# ====================================================
# 12. MAIN
# ====================================================
def main():
    st.set_page_config(page_title="GMP QMS", layout="wide")

    st.markdown(
        """
        <div class="app-header">
            <img src="https://raw.githubusercontent.com/yehyun226/final/main/image.png" width="1200">
            <h1>GMP Quality Management System</h1>
            <p>Change · Deviation · CAPA · Risk · Audit – All in One Quality System</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    

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
            "User Management (Admin)",
        ],
    )

    if menu == "Dashboard":
        page_dashboard()
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
