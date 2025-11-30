# app.py  ─────────────────────────────────────────────
import os
from datetime import datetime, date

import bcrypt
import pymysql
import pandas as pd
import streamlit as st

# ====================================================
# 0. 환경 변수 (Railway / Streamlit Cloud용)
#    Streamlit Secrets / Railway Env에 아래 키를 넣어두면 자동 사용
#    MYSQL_HOST / MYSQL_PORT / MYSQL_USER / MYSQL_PASSWORD / MYSQL_DATABASE
# ====================================================


def get_db_conn():
    return pymysql.connect(
        host=os.environ["MYSQL_HOST"],
        user=os.environ["MYSQL_USER"],
        password=os.environ["MYSQL_PASSWORD"],
        database=os.environ["MYSQL_DB"],
        port=int(os.environ["MYSQL_PORT"]),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def execute_query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    """공통 쿼리 실행 헬퍼"""
    conn = get_db_conn()
    cur = conn.cursor(dictionary=True)

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


# ====================================================
# 1. 보안 / 패스워드 유틸
# ====================================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# ====================================================
# 2. Audit Trail 로깅
# ====================================================

def log_action(user_id, action_type, object_type, object_id,
               field_name=None, old_value=None, new_value=None):
    """
    모든 주요 변경사항을 audit_logs 테이블에 기록
    """
    sql = """
    INSERT INTO audit_logs
    (user_id, action_type, object_type, object_id,
     field_name, old_value, new_value)
    VALUES (%s,%s,%s,%s,%s,%s,%s)
    """
    params = (user_id, action_type, object_type, object_id,
              field_name, old_value, new_value)
    execute_query(sql, params, commit=True)


# ====================================================
# 3. 인증 / 권한
# ====================================================

def get_user_by_username(username: str):
    sql = "SELECT * FROM users WHERE username=%s"
    return execute_query(sql, (username,), fetchone=True)


def create_user(username, password, role="OPERATOR", email=None, created_by=None):
    hashed = hash_password(password)
    sql = """
    INSERT INTO users (username, password_hash, role, email)
    VALUES (%s,%s,%s,%s)
    """
    execute_query(sql, (username, hashed, role, email), commit=True)

    # admin이 다른 유저를 만들 때 audit 남기기
    if created_by is not None:
        log_action(
            user_id=created_by,
            action_type="CREATE_USER",
            object_type="USER",
            object_id=username,
            new_value=f"role={role}, email={email}"
        )


def require_login():
    if "user" not in st.session_state:
        st.warning("이 기능을 사용하려면 로그인이 필요합니다.")
        st.stop()


def require_role(roles):
    require_login()
    user = st.session_state["user"]
    if user["role"] not in roles:
        st.error("접근 권한이 없습니다.")
        st.stop()


def login_screen():
    st.title("🔐 GMP QA e-Workflow Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("로그인"):
        user = get_user_by_username(username)
        if not user:
            st.error("존재하지 않는 계정입니다.")
            return

        if check_password(password, user["password_hash"]):
            st.session_state["user"] = {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            }
            st.success("로그인 완료")
            st.rerun()
        else:
            st.error("비밀번호가 올바르지 않습니다.")


def system_init_screen():
    """
    최초 사용자(ADMIN)가 하나도 없을 때만 실행:
    초기 관리자 계정을 만드는 화면
    """
    st.title("🚀 시스템 초기 설정 (최초 관리자 생성)")
    st.info("현재 users 테이블에 계정이 없습니다. 먼저 ADMIN 계정을 생성해야 합니다.")

    username = st.text_input("관리자 Username", value="admin")
    password = st.text_input("관리자 Password", type="password")
    email = st.text_input("관리자 Email", value="admin@example.com")

    if st.button("관리자 계정 생성"):
        if not username or not password:
            st.warning("Username / Password는 필수입니다.")
            return
        create_user(username, password, role="ADMIN", email=email, created_by=None)
        st.success("관리자 계정이 생성되었습니다. 이제 로그인해 주세요.")
        st.experimental_rerun()


# ====================================================
# 4. 각 페이지 구현
# ====================================================

# 4-1. Change Control ────────────────────────────────

def page_change_control():
    require_login()
    user = st.session_state["user"]

    st.header("📋 Change Control")

    tab_list, tab_create, tab_review = st.tabs(["목록", "생성", "상태 변경 / QA Review"])

    # 목록
    with tab_list:
        sql = "SELECT * FROM change_controls ORDER BY created_at DESC"
        rows = execute_query(sql, fetchall=True)
        st.subheader("Change 목록")
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 Change가 없습니다.")

    # 생성
    with tab_create:
        st.subheader("Change 생성")

        title = st.text_input("변경 제목")
        ctype = st.selectbox("변경 유형", ["공정 변경", "설비 변경", "시험법 변경", "원자재 변경"])
        reason = st.text_area("변경 사유")
        impacted_area = st.text_input("영향받는 공정/설비/제품")
        risk_level = st.selectbox("위험도", ["Low", "Medium", "High"])

        if st.button("Change 등록"):
            if not title or not reason:
                st.warning("제목과 사유는 필수입니다.")
            else:
                change_id = "CHG-" + datetime.now().strftime("%Y%m%d-%H%M%S")
                sql = """
                INSERT INTO change_controls
                (change_id, title, type, reason, impacted_area,
                 risk_level, status, requester_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """
                params = (change_id, title, ctype, reason, impacted_area,
                          risk_level, "Draft", user["id"])
                execute_query(sql, params, commit=True)
                log_action(user["id"], "CREATE", "CHANGE", change_id,
                           new_value=f"Change created: {title}")
                st.success(f"등록 완료 (ID: {change_id})")
                st.experimental_rerun()

    # 상태 변경 / QA Review
    with tab_review:
        st.subheader("상태 변경 / QA Review")
        change_id_input = st.text_input("Change ID 검색 (예: CHG-20251130-123000)")

        if st.button("불러오기"):
            sql = "SELECT * FROM change_controls WHERE change_id=%s"
            row = execute_query(sql, (change_id_input,), fetchone=True)
            if not row:
                st.error("해당 ID의 Change가 없습니다.")
            else:
                st.session_state["current_change"] = row

        row = st.session_state.get("current_change")
        if row:
            st.write("현재 데이터:", row)
            status_options = ["Draft", "Review", "Approved", "Rejected", "Closed"]
            new_status = st.selectbox(
                "새 상태",
                status_options,
                index=status_options.index(row["status"])
            )

            if st.button("상태 저장"):
                old_status = row["status"]
                sql = """
                UPDATE change_controls
                   SET status=%s, updated_at=NOW()
                 WHERE id=%s
                """
                execute_query(sql, (new_status, row["id"]), commit=True)

                # status_history 기록
                sql_hist = """
                INSERT INTO status_history
                (object_type, object_id, old_status, new_status, changed_by)
                VALUES (%s,%s,%s,%s,%s)
                """
                execute_query(
                    sql_hist,
                    ("CHANGE", row["change_id"], old_status, new_status, user["id"]),
                    commit=True
                )

                # audit_log 기록
                log_action(
                    user["id"],
                    "STATUS_CHANGE",
                    "CHANGE",
                    row["change_id"],
                    field_name="status",
                    old_value=old_status,
                    new_value=new_status
                )

                st.success("상태가 변경되었습니다.")
                st.experimental_rerun()


# 4-2. Deviation ─────────────────────────────────────

def page_deviation():
    require_login()
    user = st.session_state["user"]

    st.header("⚠️ Deviation 관리")

    tab_list, tab_create = st.tabs(["목록", "등록"])

    with tab_list:
        sql = "SELECT * FROM deviations ORDER BY detected_time DESC"
        rows = execute_query(sql, fetchall=True)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 Deviation이 없습니다.")

    with tab_create:
        from datetime import datetime as dt
        batch_id = st.text_input("Batch ID")
        description = st.text_area("이탈 내용")
        detected_time = st.datetime_input("발생 시각", dt.now())
        immediate_action = st.text_area("즉시 조치", "")
        status = st.selectbox("상태", ["Open", "Investigating", "Closed"])

        if st.button("Deviation 등록"):
            if not description:
                st.warning("이탈 내용은 필수입니다.")
            else:
                deviation_id = "DEV-" + dt.now().strftime("%Y%m%d-%H%M%S")
                sql = """
                INSERT INTO deviations
                (deviation_id, batch_id, description, detected_time,
                 immediate_action, status, created_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """
                params = (deviation_id, batch_id, description, detected_time,
                          immediate_action, status, user["id"])
                execute_query(sql, params, commit=True)
                log_action(user["id"], "CREATE", "DEVIATION", deviation_id,
                           new_value=f"Deviation created: {description[:50]}")
                st.success(f"등록 완료 (ID: {deviation_id})")
                st.experimental_rerun()


# 4-3. CAPA ───────────────────────────────────────────

def page_capa():
    require_login()
    user = st.session_state["user"]

    st.header("🛠 CAPA 관리")

    tab_list, tab_create = st.tabs(["목록", "CAPA 생성"])

    with tab_list:
        sql = "SELECT * FROM capas ORDER BY due_date IS NULL, due_date"
        rows = execute_query(sql, fetchall=True)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 CAPA가 없습니다.")

    with tab_create:
        from_type = st.selectbox("연계 대상 유형", ["DEVIATION", "CHANGE"])
        from_id = st.text_input("연계 Object ID (예: DEV-..., CHG-...)")
        action_plan = st.text_area("조치 계획")
        owner_name = st.text_input("담당자 이름 또는 ID")
        due_date = st.date_input("Due Date", date.today())
        progress = st.selectbox("진행 상태", ["Not Started", "In Progress", "Completed"])

        if st.button("CAPA 등록"):
            if not action_plan:
                st.warning("조치 계획은 필수입니다.")
            else:
                capa_id = "CAPA-" + datetime.now().strftime("%Y%m%d-%H%M%S")
                sql = """
                INSERT INTO capas
                (capa_id, from_type, from_id, action_plan,
                 owner_name, due_date, progress)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """
                params = (capa_id, from_type, from_id, action_plan,
                          owner_name, due_date, progress)
                execute_query(sql, params, commit=True)
                log_action(
                    user["id"], "CREATE", "CAPA", capa_id,
                    new_value=f"CAPA created: {action_plan[:50]}"
                )
                st.success(f"CAPA 등록 완료 (ID: {capa_id})")
                st.experimental_rerun()


# 4-4. Risk Assessment ────────────────────────────────

def page_risk_assessment():
    require_login()
    user = st.session_state["user"]

    st.header("📊 Risk Assessment (RPN)")

    tab_list, tab_create = st.tabs(["목록", "평가 등록"])

    with tab_list:
        sql = "SELECT * FROM risk_assessment ORDER BY created_at DESC"
        rows = execute_query(sql, fetchall=True)
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("등록된 Risk Assessment가 없습니다.")

    with tab_create:
        object_type = st.selectbox("대상 유형", ["CHANGE", "DEVIATION", "CAPA"])
        object_id = st.text_input("Object ID (예: CHG-..., DEV-..., CAPA-...)")
        severity = st.slider("Severity (심각도)", 1, 10, 5)
        occurrence = st.slider("Occurrence (발생 가능성)", 1, 10, 5)
        detection = st.slider("Detection (발견 용이성)", 1, 10, 5)

        if st.button("Risk 평가 저장"):
            if not object_id:
                st.warning("Object ID는 필수입니다.")
            else:
                rpn = severity * occurrence * detection
                sql = """
                INSERT INTO risk_assessment
                (object_type, object_id, severity, occurrence, detection, rpn, created_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """
                execute_query(
                    sql,
                    (object_type, object_id, severity, occurrence, detection, rpn, user["id"]),
                    commit=True
                )
                log_action(
                    user["id"], "CREATE", "RISK",
                    f"{object_type}:{object_id}",
                    new_value=f"RPN={rpn}"
                )
                st.success(f"저장 완료 (RPN = {rpn})")
                st.experimental_rerun()


# 4-5. 첨부파일 업로드 ────────────────────────────────

def page_attachments():
    require_login()
    user = st.session_state["user"]

    st.header("📎 첨부파일 관리 (Demo: 로컬 저장)")

    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)

    tab_list, tab_upload = st.tabs(["목록", "파일 업로드"])

    with tab_list:
        sql = "SELECT * FROM attachments ORDER BY uploaded_at DESC"
        rows = execute_query(sql, fetchall=True)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 첨부파일이 없습니다.")

    with tab_upload:
        st.subheader("파일 업로드")
        object_type = st.selectbox("연계 대상 유형", ["CHANGE", "DEVIATION", "CAPA", "OTHER"])
        object_id = st.text_input("연계 Object ID (선택)")
        file = st.file_uploader("파일 선택", type=None)

        if file and st.button("업로드 실행"):
            file_path = os.path.join(upload_dir, file.name)
            with open(file_path, "wb") as f:
                f.write(file.read())

            sql = """
            INSERT INTO attachments
            (object_type, object_id, file_name, file_path, uploaded_by)
            VALUES (%s,%s,%s,%s,%s)
            """
            execute_query(
                sql,
                (object_type, object_id, file.name, file_path, user["id"]),
                commit=True
            )
            log_action(
                user["id"], "UPLOAD", "ATTACHMENT",
                file.name,
                new_value=f"{object_type}:{object_id}"
            )
            st.success("업로드 완료")
            st.experimental_rerun()


# 4-6. Audit Trail 조회 ───────────────────────────────

def page_audit_trail():
    require_login()
    # 필요하면 QA/ADMIN만
    # require_role(["QA", "ADMIN"])

    st.header("🧾 Audit Trail")

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
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.info("표시할 Audit 로그가 없습니다.")


# 4-7. 사용자 관리 ────────────────────────────────────

def page_user_management():
    require_role(["ADMIN"])
    admin = st.session_state["user"]

    st.header("👤 사용자 관리 (ADMIN 전용)")

    tab_list, tab_create = st.tabs(["사용자 목록", "새 사용자 생성"])

    with tab_list:
        sql = "SELECT id, username, role, email, created_at FROM users ORDER BY id"
        rows = execute_query(sql, fetchall=True)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("등록된 사용자가 없습니다.")

    with tab_create:
        st.subheader("새 사용자 생성")

        username = st.text_input("Username")
        password = st.text_input("초기 Password", type="password")
        email = st.text_input("Email")
        role = st.selectbox("Role", ["OPERATOR", "QA", "QC", "ADMIN"])

        if st.button("사용자 생성"):
            if not username or not password:
                st.warning("Username / Password는 필수입니다.")
            else:
                create_user(username, password, role=role, email=email, created_by=admin["id"])
                st.success("사용자가 생성되었습니다.")
                st.experimental_rerun()


# 4-8. 간단 Dashboard (선택) ──────────────────────────

def page_dashboard():
    require_login()
    st.header("📊 QA Dashboard (요약)")

    # Change status 요약
    changes = execute_query(
        "SELECT status, COUNT(*) AS cnt FROM change_controls GROUP BY status",
        fetchall=True
    )
    deviations = execute_query(
        "SELECT status, COUNT(*) AS cnt FROM deviations GROUP BY status",
        fetchall=True
    )
    capas = execute_query(
        "SELECT progress, COUNT(*) AS cnt FROM capas GROUP BY progress",
        fetchall=True
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        st.subheader("Change Status")
        if changes:
            st.dataframe(pd.DataFrame(changes), use_container_width=True)
        else:
            st.write("데이터 없음")
    with col2:
        st.subheader("Deviation Status")
        if deviations:
            st.dataframe(pd.DataFrame(deviations), use_container_width=True)
        else:
            st.write("데이터 없음")
    with col3:
        st.subheader("CAPA Progress")
        if capas:
            st.dataframe(pd.DataFrame(capas), use_container_width=True)
        else:
            st.write("데이터 없음")


# ====================================================
# 5. 메인 app() / 라우팅
# ====================================================

def main():
    st.set_page_config(page_title="GMP QA e-Workflow", layout="wide")

    # users 테이블에 사용자가 있는지 확인
    user_count_row = execute_query(
        "SELECT COUNT(*) AS cnt FROM users",
        fetchone=True
    )
    user_count = user_count_row["cnt"] if user_count_row else 0

    # 1) 최초 실행: 관리자 계정부터 만들기
    if user_count == 0 and "user" not in st.session_state:
        system_init_screen()
        return

    # 2) 로그인 안 된 상태
    if "user" not in st.session_state:
        login_screen()
        return

    # 3) 로그인 이후 메인 화면
    user = st.session_state["user"]
    st.sidebar.success(f"👤 {user['username']} ({user['role']})")

    if st.sidebar.button("로그아웃"):
        st.session_state.pop("user")
        st.experimental_rerun()

    menu = st.sidebar.radio(
        "메뉴 선택",
        [
            "Dashboard",
            "Change Control",
            "Deviations",
            "CAPA",
            "Risk Assessment",
            "Attachments",
            "Audit Trail",
            "User Management (ADMIN)"
        ]
    )

    if menu == "Dashboard":
        page_dashboard()
    elif menu == "Change Control":
        page_change_control()
    elif menu == "Deviations":
        page_deviation()
    elif menu == "CAPA":
        page_capa()
    elif menu == "Risk Assessment":
        page_risk_assessment()
    elif menu == "Attachments":
        page_attachments()
    elif menu == "Audit Trail":
        page_audit_trail()
    elif menu == "User Management (ADMIN)":
        page_user_management()


if __name__ == "__main__":
    main()
