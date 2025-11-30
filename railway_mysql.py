# db.py
import pymysql
from contextlib import contextmanager

DB_CONFIG = {
    "host": "crossover.proxy.rlwy.net",
    "user": "root",
    "password": "oNdjYvnPuehjnsxEUSgviSZdSPKIVPPA",
    "db": "railway",
    "port": 30917,
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
}

@contextmanager
def get_conn():
    conn = pymysql.connect(**DB_CONFIG)
    try:
        yield conn
    finally:
        conn.close()

def execute_query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            if commit:
                conn.commit()
            if fetchone:
                return cur.fetchone()
            if fetchall:
                return cur.fetchall()
