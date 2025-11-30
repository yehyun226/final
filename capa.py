# pages/3_CAPA.py
import streamlit as st
from datetime import date, datetime
from railway_mysql import execute_query
from login import require_login
from utils.audit import log_action, log_status_change

def list_capas():
    rows = execute_query(
        "SELECT * FROM capas ORDER BY due_date IS NULL, due_date",
        fetchall=True
    )
    st.subheader("CAPA 목록")
    st.dataframe(rows, use_container_width=True)

def create_capa(user):
    st.subheader("CAPA 생성")

    from_type = st.selectbox("연계 유형", ["Deviation","Change"])
    from_id = st.text_input("연계 ID (예: DEV-..., CHG-...)")
    action_plan = st.text_area("조치 계획")
    owner_id = st.number_input("담당자 사용자 ID", min_value=1, step=1)
    due_date = st.date_input("Due Date", date.today())

    if st.button("CAPA 등록"):
        if not action_plan:
            st.warning("조치 계획은 필수입니다.")
            return
        capa_id = "CAPA-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        sql = """
        INSERT INTO capas
        (capa_id, from_type, from_id, action_plan, owner_id, due_date, progress)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        """
        params = (capa_id, from_type, from_id, action_plan, owner_id, due_date, "Not Started")
        execute_query(sql, params, commit=True)

        log_action(user["id"], "CREATE", "CAPA", capa_id,
                   new_value=f"CAPA: {action_plan[:50]}")
        st.success(f"CAPA 등록 완료 (ID: {capa_id})")

def update_capa_status(user):
    st.subheader("CAPA 진행 상태 변경")
    capa_id = st.text_input("CAPA ID (예: CAPA-20251130-153000)")
    if st.button("CAPA 불러오기"):
        row = execute_query(
            "SELECT * FROM capas WHERE capa_id=%s",
            (capa_id,),
            fetchone=True
        )
        if not row:
            st.error("해당 CAPA가 없습니다.")
        else:
            st.session_state["current_capa"] = row

    row = st.session_state.get("current_capa")
    if row:
        st.write(row)
        progress_list = ["Not Started","In Progress","Completed","Overdue"]
        idx = progress_list.index(row["progress"]) if row["progress"] in progress_list else 0
        new_prog = st.selectbox("새 Progress", progress_list, index=idx)
        if st.button("Progress 저장"):
            old_prog = row["progress"]
            if old_prog == new_prog:
                st.info("Progress 동일")
                return
            execute_query(
                "UPDATE capas SET progress=%s WHERE id=%s",
                (new_prog, row["id"]),
                commit=True
            )
            log_status_change(
                user_id=user["id"],
                object_type="CAPA",
                object_id=row["capa_id"],
                old_status=old_prog,
                new_status=new_prog
            )
            st.success("CAPA Progress 변경 완료")

def app():
    require_login()
    user = st.session_state["user"]
    st.title("CAPA 관리")

    tab1, tab2, tab3 = st.tabs(["목록","생성","진행 상태 변경"])
    with tab1:
        list_capas()
    with tab2:
        create_capa(user)
    with tab3:
        update_capa_status(user)

if __name__ == "__main__":
    app()
