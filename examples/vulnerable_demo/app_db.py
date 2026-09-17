"""Intentionally insecure demo code for the Cullwise dashboard scan. Not real."""

import sqlite3


def get_user(request, conn: sqlite3.Connection):
    name = request.args["name"]
    cur = conn.cursor()
    # SQL injection: query built with string formatting (CWE-89).
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchall()
