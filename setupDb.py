import sqlite3

def db_setup():
    conn = sqlite3.connect('StegChatDB.db')
    c = conn.cursor()
    sql = '''
        PRAGMA foreign_keys = ON
    '''
    c.execute(sql)
    sql = '''
        CREATE TABLE User_Tokens(
            token text NOT NULL PRIMARY KEY,
            username text
        )
    '''
    c.execute(sql)
    sql = '''
        CREATE TABLE Public_Keys(
            token text NOT NULL PRIMARY KEY,
            public_key text
        )
    '''
    c.execute(sql)
    sql = '''
        CREATE TABLE Requests(
            req_id text NOT NULL PRIMARY KEY,
            requestor text,
            requesting text,
            granted boolean NOT NULL DEFAULT 0
        )
    '''
    c.execute(sql)
    sql = '''
        CREATE TABLE Sessions(
            ses_id text NOT NULL PRIMARY KEY,
            participants text
        )
    '''
    c.execute(sql)
    sql = '''
        CREATE TABLE Messages(
            session_id text NOT NULL,
            sender text,
            receiver text,
            message BLOB,
            time text,
            type text,
            steg text,
            FOREIGN KEY (session_id) REFERENCES Sessions(ses_id)
        )
    '''
    c.execute(sql)
    conn.commit()

def execute_query(sql, params, fetch):
    conn = sqlite3.connect('StegChatDB.db')
    c = conn.cursor()
    if params:
        c.execute(sql, params)
    else:
        c.execute(sql)
    if fetch:
        if fetch == 'one':
            conn.commit()
            return c.fetchone()
        elif fetch == 'all':
            conn.commit()
            return c.fetchall()
    conn.commit()