from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import sqlite3
from datetime import datetime
import uuid
import json
from setupDb import db_setup, execute_query
import logging
from flask_executor import Executor
from flask_socketio import SocketIO
from flask_socketio import send, emit

tok_sids = {}
user_sids = {}
sid_toks = {}
sid_users = {}

'''
Ideas:
    - Users can choose whether to save chat session chat logs
        - Chat logs are only saved if both users agree
        - Chat logs are requested from the server when a user ends the session and both users consent to saving the chat logs
        - Chat logs are saved on the user(s)' computer 
    - When a chat session ends, the server deletes all message and session data for that session
'''

app = Flask(__name__)
#cors = CORS(app)
executor = Executor(app)
socketio = SocketIO(app, cors_allowed_origins="*")
log = logging.getLogger('werkzeug')
log.disabled = True

@socketio.on('connect')
def handle_conn():
    print('Connected')

@socketio.on('deactivate')
def deactivate(body):
    user = body['username']
    token = body['token']
    sql = '''
        SELECT *
        FROM User_Tokens
        WHERE (username = ? AND token = ?)
    '''
    res = execute_query(sql, (user, token), 'one')
    if res is not None:
        sql = '''
            DELETE FROM User_Tokens WHERE (username = ? AND token = ?)
        '''
        execute_query(sql, (user, token), None)
        emit('res-deactivate', {'Success': True})
    else:
        emit('res-deactivate', {'Success': False})

@socketio.on('disconnect')
def handle_disconnect():
    global user_sids, tok_sids, sid_toks, sid_users
    if request.sid in sid_toks:
        user = sid_users[request.sid]
        tok = sid_toks[request.sid]
        del sid_users[request.sid]
        del sid_toks[request.sid]
        del tok_sids[tok]
        del user_sids[user]

        sql = '''
            DELETE FROM Public_Keys WHERE token = ?
        '''
        execute_query(sql, (tok,), None)

        sql = '''
            DELETE FROM Requests WHERE (requestor = ? OR requesting = ?)
        '''
        execute_query(sql, (tok, tok), None)

        sql = f'''
            SELECT ses_id
            FROM Sessions
            WHERE (participants LIKE '%,{tok}' OR participants LIKE '{tok},%')
        '''
        res = execute_query(sql, None, 'all')
        for x in res:
            sid = x[0]
            sql = '''
                DELETE FROM Messages WHERE session_id = ?
            '''
            execute_query(sql, (sid,), None)
            sql = '''
                DELETE FROM Sessions WHERE ses_id = ?
            '''
            execute_query(sql, (sid,), None)

        print(f"{user} disconnected")
    
    print(f"Disconnected")

@socketio.on('check-username')
def check_username(body):
    username = body['username']
    sql = '''
        SELECT username
        FROM User_Tokens
        WHERE username = ?
    '''
    res = execute_query(sql, (username,), 'one')
    if res is not None:
        emit('res-check-username', {'result': True})
    else:
        emit('res-check-username', {'result': False})

@socketio.on('authenticate')
def handle_auth(body):
    global user_sids, tok_sids, sid_toks, sid_users
    token = body['token']
    username = body['username']
    sql = '''
        SELECT token
        FROM User_Tokens
        WHERE token = ?
    '''
    res = execute_query(sql, (token,), 'one')
    if res is not None:
        user_sids[username] = request.sid
        tok_sids[token] = request.sid
        sid_toks[request.sid] = token
        sid_users[request.sid] = username
        emit('connected', True)
    else:
        emit('connected', False)

"""
Parameters:
    - username: Requestor's username
    - token: Requestor's old token (can be empty if requestor has never used the application)
Functionality:
    - Returns a token for the requestor to use
Conditions:
    - If the token parameter is empty and username doesn't exist in User_Tokens, then generates and returns a token
    - If the token parameter is empty and username exists in User_Tokens, then server returns 'User already exists'
    - If the token parameter is the same as the username's token in User_Tokens, then generates a new token and returns that token
      while updating the value for token to the new one in User_Tokens
    - If the token parameter is non-empty but not the same as in User_Tokens, then server returns 'Permission denied'
"""
@socketio.on('get-token')
def get_token(body):
    print(body)
    username = body['username']
    tok = None
    if 'token' in body: tok = body['token']
    sql = '''
        SELECT username, token
        FROM User_Tokens
        WHERE username = ?
    '''
    res = execute_query(sql, (username,), 'one')
    if res is None:
        token = str(uuid.uuid4())
        sql = '''
            INSERT INTO User_Tokens VALUES(?,?)
        '''
        execute_query(sql, (token, username), None)
        print(f"Username: {username}, Generated Token: {token}")
        emit('res-get-token', {'token': token})
        return
    else:
        username, token = res
        if token == tok:
            new_token = str(uuid.uuid4())
            sql = '''
                UPDATE User_Tokens
                SET token = ?
                WHERE username = ?
            '''
            execute_query(sql, (new_token, username), None)

            sql = '''
                UPDATE Requests
                SET requestor = ?
                WHERE requestor = ?
            '''
            execute_query(sql, (new_token, token), None)

            sql = '''
                UPDATE Requests
                SET requesting = ?
                WHERE requesting = ?
            '''
            execute_query(sql, (new_token, token), None)

            print(f"Username: {username}, New Token: {new_token}")
            emit('res-get-token', {'token': new_token})
            return
        elif token == '':
            emit('res-get-token', {'Message': 'Username already exists'})
            return
        else:
            emit('res-get-token', {'Message': 'Permission denied.'})

"""
Parameters:
    - ses_id: A preferably valid session ID
    - target: The target who's public key is to be retrieved
Functionality:
    - Return the public key of the target
Conditions:
    - If ses_id doesn't exist in Sessions then returns 'Invalid Session ID.'
    - If ses_id is valid but target isn't in the participants of the Session then returns 'Permission denied.'
    - If target doesn't exist in User_Tokens then returns 'User doesn't exist'
    - If ses_id is valid and target is a participant of the Session then returns the public key of the target
"""
@socketio.on('get-pkey')
def get_pkey(body):
    ses_id = body['ses_id']
    target = body['target']
    sql = '''
        SELECT token
        FROM User_Tokens
        WHERE username = ?
    '''
    res = execute_query(sql, (target,), 'one')
    if res is not None:
        target = res[0]
        sql = '''
            SELECT *
            FROM Sessions
            WHERE ses_id = ?
        '''
        res = execute_query(sql, (ses_id,), 'one')
        if res is not None:
            ses_id, participants = res
            if target in participants.split(','):
                sql = '''
                    SELECT public_key
                    FROM Public_Keys
                    WHERE token = ?
                '''
                pkey = execute_query(sql, (target,), 'one')[0]
                emit('res-get-pkey', {"pkey": pkey, "target": body['target'], "ses_id": body['ses_id']})
                return
            else:
               emit('res-get-pkey', {"Message": "Permission denied."})
               return
        else:
            emit('res-get-pkey', {"Message": "Invalid Session ID."})
            return
    else:
        emit('res-get-pkey', {"Message:" "User doesn't exist."})
        return

@socketio.on('my-pkey')
def store_my_pkey(body):
    token = body['token']
    sql = '''
        SELECT token
        FROM Public_Keys
        WHERE token = ?
    '''
    res = execute_query(sql, (token,), 'one')
    if res is not None:
        return
    sql = '''
        SELECT username
        FROM User_Tokens
        WHERE token = ?
    '''
    res = execute_query(sql, (token,), 'one')
    if res is not None:
        pkey = body['pkey']
        sql = '''
            INSERT INTO Public_Keys VALUES(?,?)
        '''
        execute_query(sql, (token, pkey), None)
        emit('res-my-pkey', {"Success": True})
        return
    else:
        emit('res-my-pkey', {"Message": "Invalid token."})
        return

@socketio.on('my-requests')
def get_chat_requests(body):
    token = body['token']
    sql = '''
        SELECT Requests.req_id, User_Tokens.username, Requests.granted
        FROM Requests
        LEFT OUTER JOIN User_Tokens
        ON (Requests.requesting = ? AND User_Tokens.token = Requests.requestor)
    '''
    res = execute_query(sql, (token,), 'all')
    if len(res) > 0:
        reqs = []
        for r in res:
            req_id, requestor, granted = r
            if granted == 0:
                reqs.append({'req_id': req_id, 'requestor': requestor})
        emit('res-my-requests', {'requests': reqs})
        return
    else:
        emit('res-my-requests', {"Message": "No chat requests so far."})
        return

@socketio.on('request')
def request_chat(body):
    global user_sids, tok_sids
    requestor = body['token']
    requesting = body['requesting']
    sql = '''
        SELECT token
        FROM User_Tokens
        WHERE username = ?
    '''
    res = execute_query(sql, (requesting,), 'one')
    if res is not None:
        requesting = res[0]
        sql = '''
            SELECT req_id
            FROM Requests
            WHERE (requestor = ? AND requesting = ?)
        '''
        res = execute_query(sql, (requesting, requestor), 'one')
        if res is None:
            sql = '''
                SELECT req_id
                FROM Requests
                WHERE (requestor = ? AND requesting = ?)
            '''
            res = execute_query(sql, (requestor, requesting), 'one')
            if res is None:
                sql = '''
                    INSERT INTO Requests VALUES(?,?,?,?)
                '''
                req_id = str(uuid.uuid4())
                execute_query(sql, (req_id, requestor, requesting, 0), None)
                emit('request-res', {"Success": True, "req_id": req_id, "user": body['requesting']})
                if requesting in tok_sids:
                    emit('check-requests', room=tok_sids[requesting])
                return
            else:
                emit('request-res', {"Message": "You have already requested to chat with this person."})
                return
        else:
            emit('request-res', {"Message": "This person has already requested to chat with you."})
            return
    else:
        emit('request-res', {"Message": "User doesn't exist."})
        return
    emit('request-res', {"Message": "Invalid token."})

@socketio.on('accept-request')
def accept_request(body):
    req_id = body['obj']['req_id']
    token = body['token']
    sql = '''
        SELECT *
        FROM Requests
        WHERE req_id = ?
    '''
    res = execute_query(sql, (req_id,), 'one')
    if res is not None:
        req_id, requestor, requesting, granted = res
        if requesting == token and granted == 0:
            sql = '''
                UPDATE Requests
                SET granted = 1
                WHERE req_id = ?
            '''
            execute_query(sql, (req_id,), None)
            sql = '''
                INSERT INTO Sessions VALUES(?,?)
            '''
            ses_id = str(uuid.uuid4())
            execute_query(sql, (ses_id, requestor + ',' + requesting), None)
            emit('res-accept-request', {"Success": True, "ses_id": ses_id, "obj": body['obj']})
            if requestor in tok_sids:
                emit('request-accepted', {"req_id": req_id, "ses_id": ses_id}, room=tok_sids[requestor])
            return
        elif granted == 1:
            emit('res-accept-request', {"Message": "Request already accepted."})
            return
        else:
            emit('res-accept-request', {"Message": "Permission denied."})
            return
    else:
        emit('res-accept-request', {"Message": "Invalid Request ID."})

@socketio.on('my-sent-requests')
def get_sent_reqs(body):
    token = body['token']
    sql = '''
        SELECT Requests.req_id, User_Tokens.username
        FROM Requests
        LEFT OUTER JOIN User_Tokens
        ON (Requests.requestor = ? AND User_Tokens.token = Requests.requesting)
    '''
    res = execute_query(sql, (token,), 'all')
    print(res)
    if len(res) > 0:
        requests = []
        for x in res:
            req_id, user = x
            if user:
                requests.append({
                    "username": user,
                    "req_id": req_id
                })
        emit('res-my-sent-requests', {'requests': requests})
    else:
        emit('res-my-sent-requests', {'message': 'No sent requests'})

@socketio.on('check-request')
def check_req(body):
    req_id = body['obj']['req_id']
    token = body['token']
    sql = '''
        SELECT *
        FROM Requests
        WHERE req_id = ?
    '''
    res = execute_query(sql, (req_id,), 'one')
    if res is not None:
        req_id, requestor, requesting, granted = res
        if granted == 1 and requestor == token:
            sql = '''
                SELECT ses_id 
                FROM Sessions
                WHERE participants = ?
            '''
            ses_id = execute_query(sql, (requestor + ',' + requesting,), 'one')[0]
            emit('res-check-request', {"Message": "Chat Request has been accepted", "ses_id": ses_id, "obj": body['obj']})
            return
        elif granted == 0 and requestor == token:
            emit('res-check-request', {"Message": "Chat Request not accepted yet."})
            return
        else:
            emit('res-check-request', {"Message": "Permission denied."})
            return
    else:
        emit('res-check-request', {"Message": "Invalid Request ID."})
        return

@socketio.on('message')
def msg_endpoint(body):
    
    msg = body['msg']
    sender = body['token']
    receiver = body['receiver']
    time = datetime.now().strftime('%d/%m/%Y %I:%M:%S %p')
    ses_id = body['ses_id']
    msg_type = body['type']
    steg = body['steg']
    
    sql = '''
        SELECT *
        FROM User_Tokens
        WHERE token = ?
    '''
    res = execute_query(sql, (sender,), 'one')
    if res is None:
        emit('res-message', {"Message": "Invalid token"})
        return
    sql = '''
        SELECT token
        FROM User_Tokens
        WHERE username = ?
    '''
    res = execute_query(sql, (receiver,), 'one')
    if res is not None:
        receiver = res[0]
        sql = '''
            SELECT participants
            FROM Sessions
            WHERE ses_id = ?
        '''
        res = execute_query(sql, (ses_id,), 'one')
        if res is not None:
            if receiver in res[0].split(','):
                sql = '''
                    SELECT *
                    FROM Messages
                    WHERE (
                        session_id = ? AND 
                        sender = ? AND 
                        receiver = ? AND 
                        message = ? AND 
                        time = ? AND 
                        type = ? AND 
                        steg = ?
                    )
                '''
                res = execute_query(sql, (ses_id, sender, receiver, msg.encode(), time, msg_type, steg), 'one')
                if res is None:
                    sql = '''
                        INSERT INTO Messages VALUES(?,?,?,?,?,?,?)
                    '''
                    execute_query(sql, (ses_id, sender, receiver, msg.encode(), time, msg_type, steg), None)
                    emit('check-messages', {"ses_id": ses_id})
                    if body['receiver'] in user_sids:
                        emit('check-messages', {"ses_id": ses_id}, room=user_sids[body['receiver']])
                else:
                    emit('res-message', {"Message": "Duplicate message."})
            else:
                emit('res-message', {"Message": "Permission denied."})
        else:
            emit('res-message', {"Message": "Invalid Session ID."})
    else:
        emit('res-message', {"Message": "User doesn't exist."})

@socketio.on('get-messages')
def get_msgs(body):
    ses_id = body['ses_id']
    last_msg = int(body['last_msg'])
    sql = '''
        SELECT *
        FROM Messages
        WHERE session_id = ?
    '''
    res = execute_query(sql, (ses_id,), 'all')
    if len(res) > 0:
        msgs = []
        for r in res:
            ses_id, sender, receiver, msg, time, msg_type, steg = r
            sql = '''
                SELECT username
                FROM User_Tokens
                where token = ?
            '''
            sender = execute_query(sql, (sender,), 'one')[0]
            receiver = execute_query(sql, (receiver,), 'one')[0]
            msgs.append({'ses_id': ses_id, 'msg': msg.decode(), 'time': time, 'sender': sender, 'receiver': receiver, 'type': msg_type, 'steg': steg})
        emit('res-get-messages', {'messages': msgs[last_msg:]})
    else:
        emit('res-get-messages', {'Message': 'No messages yet'})

def setup():
    try:
        f = open('StegChatDB.db')
        f.close()
    except:
        db_setup()  

if __name__ == '__main__':

    try:
        f = open('StegChatDB.db')
        f.close()
    except:
        db_setup()

    #app.run(host='0.0.0.0', port='5000')
    #socketio.run(app, host='0.0.0.0', port=5000)
    app.run(host='0.0.0.0')
