from flask import Flask, render_template, request, redirect, url_for, session, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms, close_room
import logging
import secrets # Used for app.secret_key

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
# IMPORTANT: Change this to a strong, random key in production!
app.secret_key = secrets.token_hex(16) 
socketio = SocketIO(app)

# Global data stores
# In a real app, use a database (e.g., SQLite, PostgreSQL) for persistent user data
users = {} # Stores user credentials and profile info {username: {password: '...', bio: '...', interests: '...'}}
online_users = set() # Set of usernames currently online
sid_to_username = {} # Maps Socket.IO SID to username
username_to_sid = {} # Maps username to Socket.IO SID
user_call_status = {} # {username: True/False} (True if in call, False if not)

message_history = [] # Stores public chat messages
MAX_HISTORY_LENGTH = 100 # Max messages to store in history

voice_call_queue = [] # Queue for users requesting a voice call
call_sessions = {} # To store active call sessions: {username: partner_username}


# --- HELPER FUNCTIONS ---
# This function sends the updated list of online users and their call status to all clients.
# It MUST be defined BEFORE any routes or event handlers call it.
def send_updated_user_list():
    users_with_status = []
    for user in online_users:
        status = 'in_call' if user_call_status.get(user, False) else 'online'
        users_with_status.append({'username': user, 'status': status})
    emit('update_user_list', {'users': users_with_status}, broadcast=True)

# This function attempts to match two users from the voice call queue.
# It doesn't need to be placed immediately after its definition; just needs to be defined before called.
def try_match_users():
    if len(voice_call_queue) >= 2:
        offerer_username = voice_call_queue.pop(0) # This user will create the offer
        answerer_username = voice_call_queue.pop(0) # This user will receive the offer and create an answer
        
        logging.info(f'Matched for voice call: {offerer_username} and {answerer_username}')
        
        offerer_sid = username_to_sid.get(offerer_username)
        answerer_sid = username_to_sid.get(answerer_username)
        
        if offerer_sid and answerer_sid:
            # Store the active call session for both users
            call_sessions[offerer_username] = answerer_username
            call_sessions[answerer_username] = offerer_username
            
            # Update call status for both users
            user_call_status[offerer_username] = True
            user_call_status[answerer_username] = True
            send_updated_user_list() # Broadcast the status change
            
            # Notify the offerer to START the WebRTC process (create and send offer)
            emit('start_voice_call', {'peer': answerer_username}, room=offerer_sid)
            
            # Notify the answerer that they have been matched and should WAIT for an offer
            emit('system_message', {'message': f'You have been matched with {offerer_username}. Waiting for their call to connect...'}, room=answerer_sid)
            
            logging.info(f'Active call sessions: {call_sessions}')
        else:
            logging.warning(f'Error: Could not find session IDs for {offerer_username} or {answerer_username}. Re-queuing valid users if possible.')
            # Re-queue users if their SIDs are no longer valid (e.g., they disconnected)
            if offerer_username in online_users and offerer_username not in voice_call_queue:
                voice_call_queue.append(offerer_username)
            if answerer_username in online_users and answerer_username not in voice_call_queue:
                voice_call_queue.append(answerer_username)
            
            # This 'request.sid' might not be the actual initiator if called from try_match_users directly,
            # but it provides a fallback to notify *some* connected user.
            current_requester_sid = request.sid
            if current_requester_sid in sid_to_username:
                emit('system_message', {'message': 'Matching failed, a user disconnected. Please try again.'}, room=current_requester_sid)

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html') # Assuming you have an index.html

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return "Username already taken. Please choose another."
        else:
            users[username] = {
                'password': password,
                'bio': '', # Initialize bio
                'interests': '' # Initialize interests
            }
            logging.info(f"User {username} registered.")
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            session['username'] = username
            logging.info(f"User {username} logged in.")
            return redirect(url_for('chat')) # Redirect to chat after successful login
        else:
            return "Invalid username or password."
    return render_template('login.html')

# Removed dashboard route as 'chat' serves as the main logged-in landing page
# @app.route('/dashboard')
# def dashboard():
#     if 'username' in session:
#         username = session['username']
#         user_data = users.get(username)
#         if user_data:
#             bio = user_data.get('bio', 'No bio available.')
#             return f"Logged in as {username}! Welcome to your dashboard.<br>Your bio: {bio}"
#         else:
#             return "Error: User data not found."
#     else:
#         return "Please log in to access this page."

@app.route('/profile')
def profile():
    if 'username' in session:
        username = session['username']
        user_data = users.get(username)
        if user_data:
            return render_template('profile.html', username=username, user=user_data)
        else:
            return "Error: User data not found."
    else:
        return redirect(url_for('login'))

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_data = users.get(username)

    if not user_data:
        return "Error: User data not found."

    if request.method == 'POST':
        user_data['bio'] = request.form.get('bio', '')
        user_data['interests'] = request.form.get('interests', '')
        logging.info(f"User {username}'s profile updated.")
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html', user=user_data)

# @app.route('/profile/edit', methods=['POST']) # This route is merged into edit_profile
# def update_profile():
#     pass


@app.route('/chat')
def chat():
    if 'username' in session:
        response = make_response(render_template('chat.html'))
        # Adjust Content-Security-Policy if you are getting errors related to scripts or styles.
        # 'unsafe-inline' is generally discouraged but often necessary for simple Flask templates with inline JS/CSS.
        # For WebRTC, ensure 'connect-src' includes 'self' and 'ws://*' for WebSocket, and potentially 'blob:' for media streams.
        response.headers['Content-Security-Policy'] = "default-src 'self'; connect-src 'self' ws://* blob:; script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        return response
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username:
        logging.info(f"User {username} logged out.")
    return redirect(url_for('login'))


# --- Socket.IO Event Handlers ---

@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username:
        logging.info(f'{username} has connected with session ID: {request.sid}')
        online_users.add(username)
        sid_to_username[request.sid] = username
        username_to_sid[username] = request.sid
        
        # Initialize user's call status to False if not already set
        if username not in user_call_status:
            user_call_status[username] = False

        emit('user_connected_message', {'message': f'<span class="status-message">{username} has joined the chat.</span>'}, broadcast=True)
        send_updated_user_list() # Broadcast the updated user list
        
        emit('load_history', {'history': message_history}, room=request.sid)
        emit('current_user_info', {'username': username}, room=request.sid)
    else:
        logging.info('Anonymous user connected (no username in session).')
        # Consider disconnecting anonymous users or prompting login here if desired.




@socketio.on('disconnect')
def handle_disconnect():
    username = sid_to_username.get(request.sid)
    if username:
        logging.info(f'{username} has disconnected with session ID: {request.sid}')
        online_users.discard(username)
        del sid_to_username[request.sid]
        if username in username_to_sid:
            del username_to_sid[username]
        
        # Remove from call status tracking
        if username in user_call_status:
            del user_call_status[username]

        emit('user_disconnected_message', {'message': f'<span class="status-message">{username} has left the chat.</span>'}, broadcast=True)
        send_updated_user_list() # Broadcast the updated user list

        # Handle if the disconnecting user was in the voice call queue
        if username in voice_call_queue:
            voice_call_queue.remove(username)
            logging.info(f'{username} removed from voice call queue on disconnect.')

        # If in a call, notify the other party and clean up
        if username in call_sessions:
            partner_username = call_sessions.get(username)
            if partner_username:
                partner_sid = username_to_sid.get(partner_username)
                if partner_sid:
                    logging.info(f'Notifying {partner_username} (SID: {partner_sid}) that {username} disconnected from call.')
                    emit('call_ended_by_peer', {'peer': username}, room=partner_sid)

                # Clean up call_sessions for both sides
                if username in call_sessions:
                    del call_sessions[username]
                if partner_username in call_sessions:
                    del call_sessions[partner_username]

                # Update partner's call status
                if partner_username in user_call_status:
                    user_call_status[partner_username] = False
                send_updated_user_list() # Broadcast the change
                
                logging.info(f'Call between {username} and {partner_username} ended due to disconnect.')
            else:
                logging.warning(f"Disconnecting user {username} was in call_sessions but partner not found.")
            # Ensure own entry is removed if partner was already gone
            if username in call_sessions:
                del call_sessions[username]
    else:
        logging.info('Anonymous user disconnected.')


@socketio.on('send_message')
def handle_send_message(data):
    username = session.get('username')
    message = data.get('message')
    if not username or not message:
        return

  
               
    emit('receive_message', {'username': username, 'message': message}, broadcast=True)
    logging.info(f'{username}: {message}')
    message_history.append({'username': username, 'message': message})
    if len(message_history) > MAX_HISTORY_LENGTH:
        message_history.pop(0)


@socketio.on('send_private_message')
def handle_send_private_message(data):
    sender_username = session.get('username')
    recipient_username = data.get('recipient')
    message = data.get('message')

    if not sender_username or not recipient_username or not message:
        logging.warning(f"Invalid private message data from {sender_username}: {data}")
        emit('system_message', {'message': 'Error sending private message: Missing data.'}, room=request.sid)
        return

    recipient_sid = username_to_sid.get(recipient_username)
    sender_sid = username_to_sid.get(sender_username)

    if recipient_sid:
        logging.info(f'(Private DM) {sender_username} -> {recipient_username}: {message}')
        emit('receive_private_message', {'sender': sender_username, 'message': message}, room=recipient_sid)
        # Emit back to the sender (so they see their own message in the DM window)
        emit('receive_private_message', {'sender': sender_username, 'message': message}, room=sender_sid)
        # Emit back to the sender (so they see their own message in the DM window)
        
    else:
        logging.info(f'Private message to {recipient_username} failed: User offline or not found.')
        emit('system_message', {'message': f'<span class="status-message">User "{recipient_username}" is offline or not found.</span>'}, room=request.sid)


@socketio.on('request_voice_call')
def handle_request_voice_call():
    username = session.get('username')
    if not username:
        emit('system_message', {'message': 'You must be logged in to request a call.'}, room=request.sid)
        return

    if username in call_sessions:
        emit('system_message', {'message': 'You are already in a voice call!'}, room=request.sid)
        return

    if username not in voice_call_queue:
        voice_call_queue.append(username)
        logging.info(f'{username} joined the voice call queue. Queue: {voice_call_queue}')
        emit('system_message', {'message': 'You have joined the call queue. Waiting for a match...'}, room=request.sid)
        send_updated_user_list() # Update list to potentially show "waiting" status (if you add it)
        try_match_users() # Try to match immediately
    else:
        emit('system_message', {'message': 'You are already in the voice call queue.'}, room=request.sid)


@socketio.on('request_skip_call')
def handle_request_skip_call():
    username = session.get('username')
    if not username:
        emit('system_message', {'message': 'You must be logged in to skip a call.'}, room=request.sid)
        return

    if username in voice_call_queue:
        voice_call_queue.remove(username)
        logging.info(f'{username} left the voice call queue. Queue: {voice_call_queue}')
        emit('system_message', {'message': 'You have left the voice call queue.'}, room=request.sid)
        send_updated_user_list() # Update status
    elif username in call_sessions:
        emit('system_message', {'message': 'You are currently in an active call. Use "End Call" instead of "Skip".'}, room=request.sid)
    else:
        emit('system_message', {'message': 'You are not currently in a voice call or queue to skip.'}, room=request.sid)


@socketio.on('end_voice_call')
def handle_end_voice_call():
    username = session.get('username')
    if not username:
        emit('system_message', {'message': 'You must be logged in to end a call.'}, room=request.sid)
        return

    if username in call_sessions:
        partner_username = call_sessions[username]
        partner_sid = username_to_sid.get(partner_username)

        logging.info(f'{username} is ending the call with {partner_username}.')

        # Clean up call_sessions for both sides
        if username in call_sessions:
            del call_sessions[username]
        if partner_username in call_sessions:
            del call_sessions[partner_username]

        # Remove from queue (if somehow still there)
        if username in voice_call_queue:
            voice_call_queue.remove(username)
        if partner_username in voice_call_queue:
            voice_call_queue.remove(partner_username)

        # Set call status for both users to False
        if username in user_call_status:
            user_call_status[username] = False
        if partner_username in user_call_status:
            user_call_status[partner_username] = False
        send_updated_user_list() # Broadcast the status change
        
        emit('system_message', {'message': 'Voice call ended by you.'}, room=request.sid)

        # Notify the partner that the call has ended
        if partner_sid:
            logging.info(f'Notifying partner {partner_username} (SID: {partner_sid}) that call ended.')
            emit('call_ended_by_peer', {'peer': username}, room=partner_sid)
        else:
            logging.info(f"Partner {partner_username} not found (might have disconnected).")

        logging.info(f'Active call sessions: {call_sessions}')
    else:
        emit('system_message', {'message': 'You are not currently in a voice call.'}, room=request.sid)


@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    username = session.get('username')
    if not username: return # Unauthenticated user

    peer_username = data.get('peer')
    candidate = data.get('candidate')

    if not peer_username or not candidate:
        logging.warning(f"Invalid ICE candidate data from {username}: {data}")
        return

    # Ensure the sender is actually in a call with the peer they are sending to
    if call_sessions.get(username) != peer_username:
        logging.warning(f"ICE candidate from {username} to {peer_username} but not in active call with that peer.")
        return # Ignore if not in an active call with this peer

    peer_sid = username_to_sid.get(peer_username)
    if peer_sid:
        logging.debug(f'Relaying ICE candidate from {username} to {peer_username}')
        emit('ice_candidate', {'candidate': candidate, 'sender': username}, room=peer_sid)
    else:
        logging.warning(f'Error: Could not find session ID for peer {peer_username} when relaying ICE candidate.')


@socketio.on('offer')
def handle_offer(data):
    username = session.get('username') # The offerer's username
    if not username: return # Unauthenticated user

    peer_username = data.get('peer') # The intended recipient (answerer)
    offer_sdp = data.get('sdp')

    if not peer_username or not offer_sdp:
        logging.warning(f"Invalid offer data from {username}: {data}")
        return

    # Ensure the sender is actually in a call with the peer they are sending to
    if call_sessions.get(username) != peer_username:
        logging.warning(f"Offer from {username} to {peer_username} but not in active call with that peer.")
        return # Ignore if not in an active call with this peer

    peer_sid = username_to_sid.get(peer_username)
    if peer_sid:
        logging.info(f'Relaying Offer from {username} to {peer_username}')
        emit('offer', {'sdp': offer_sdp, 'sender': username}, room=peer_sid)
    else:
        logging.warning(f'Offer to {peer_username} failed: User offline or not found.')
        emit('system_message', {'message': f'Voice call failed: {peer_username} is offline.'}, room=request.sid)
        # Clean up offerer's side if recipient is not found
        if username in call_sessions:
            del call_sessions[username]
            if username in user_call_status:
                user_call_status[username] = False
                send_updated_user_list() # Revert status
        logging.info(f"Active call sessions after failed offer: {call_sessions}")


@socketio.on('answer')
def handle_answer(data):
    username = session.get('username') # The answerer's username
    if not username: return # Unauthenticated user

    peer_username = data.get('peer') # The original offerer's username
    answer_sdp = data.get('sdp')

    logging.info(f"\n--- Received Answer Event ---")
    logging.info(f"   From User: {username}")
    logging.info(f"   From SID: {request.sid}")
    logging.info(f"   Received Data: {data}")
    logging.info(f"Intended peer (original offerer): {peer_username}")

    if not peer_username or not answer_sdp:
        logging.warning("Error: Missing 'peer' or 'sdp' in answer data.")
        return

    # Ensure the sender is actually in a call with the peer they are sending to
    if call_sessions.get(username) != peer_username:
        logging.warning(f"Answer from {username} to {peer_username} but not in active call with that peer.")
        return # Ignore if not in an active call with this peer

    peer_sid = username_to_sid.get(peer_username)
    if peer_sid:
        logging.info(f'Relaying Answer from {username} to {peer_username} (Target SID: {peer_sid})')
        emit('answer', {'sdp': answer_sdp, 'sender': username}, room=peer_sid)
        logging.info(f"   Answer relayed.")
    else:
        logging.warning(f'Error: Could not find session ID for peer {peer_username} when relaying answer.')
    logging.info(f"--- End Answer Event ---\n")


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)