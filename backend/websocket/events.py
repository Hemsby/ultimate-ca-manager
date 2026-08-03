"""
WebSocket events handler and emitter.
Provides real-time event broadcasting to connected clients.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from functools import wraps

from flask import request, current_app, session
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect

from .event_types import EventType
from utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

# SocketIO instance - initialized in init_websocket()
socketio = SocketIO()

# Connected clients tracking
connected_clients: Dict[str, Dict[str, Any]] = {}

# Minimum permission required to open a socket. Every event this module emits is
# derived from CA/certificate state, so a caller that cannot read certificates
# has no legitimate reason to hold a subscription.
_SOCKET_MIN_PERMISSION = 'read:certificates'


def init_websocket(app):
    """Initialize WebSocket with Flask app."""
    # Use CORS origins from app config (don't allow "*")
    cors_origins = app.config.get('CORS_ORIGINS', ["https://localhost:8443"])
    socketio.init_app(
        app,
        cors_allowed_origins=cors_origins,
        async_mode='gevent',
        manage_session=False,
        logger=True,
        engineio_logger=False,
        ping_timeout=60,
        ping_interval=25
    )

    logger.info("WebSocket initialized with gevent async mode")
    return socketio


def _resolve_user_from_session():
    """Resolve the authenticated user from the Flask session.

    Delegates to ``AuthManager.verify_session`` so a socket is held to the same
    inactivity and absolute-lifetime rules as the REST API. Reading
    ``session['user_id']`` directly would let an expired session keep a
    long-lived subscription open indefinitely.

    Returns ``(user_id, username, permissions)``; ``(None, None, [])`` when
    unauthenticated.
    """
    if 'user_id' not in session:
        return None, None, []

    try:
        from auth.unified import AuthManager
        result = AuthManager().verify_session()
    except Exception as e:
        logger.warning(f"WebSocket session verification failed: {e}")
        return None, None, []

    if not result:
        return None, None, []

    user = result.get('user')
    return (
        result.get('user_id'),
        getattr(user, 'username', None),
        result.get('permissions') or [],
    )


def _extract_handshake_token(auth=None):
    """Pull an API key out of the SocketIO handshake.

    Browsers cannot set an ``Authorization``/``X-API-Key`` header on the
    WebSocket upgrade, so socket.io clients pass credentials either in the
    query string (``io(url, {query: {token: ...}})``) or in the ``auth``
    payload (``io(url, {auth: {token: ...}})``). The ``auth`` payload is
    delivered to the ``connect`` handler as an argument -- it is NOT present in
    ``request.args`` -- so it has to be threaded in from the caller.
    """
    if isinstance(auth, dict):
        token = auth.get('token') or auth.get('api_key')
        if token:
            return token

    token = request.args.get('token')
    if token:
        return token

    # Some clients serialise the auth dict into a single query parameter.
    raw = request.args.get('auth')
    if raw:
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            return None
        if isinstance(parsed, dict):
            return parsed.get('token') or parsed.get('api_key')

    return None


def _resolve_user_from_api_key(auth=None):
    """Resolve a user from an API key supplied on the handshake.

    ``verify_api_key`` is a method on ``AuthManager`` (there is no module-level
    function of that name) and it returns a dict -- not a User -- so the result
    is unpacked accordingly.

    Returns ``(user_id, username, permissions)``.
    """
    token = _extract_handshake_token(auth)
    if not token:
        return None, None, []

    try:
        from auth.unified import AuthManager
        result = AuthManager().verify_api_key(token)
    except Exception as e:
        logger.warning(f"WebSocket API key verification failed: {e}")
        return None, None, []

    if not result:
        return None, None, []

    user = result.get('user')
    return (
        result.get('user_id'),
        getattr(user, 'username', None),
        result.get('permissions') or [],
    )


def _authenticate_handshake(auth=None) -> Tuple[Optional[Any], Optional[str], list]:
    """Authenticate a socket handshake via session cookie, then API key."""
    user_id, username, permissions = _resolve_user_from_session()
    if user_id is None:
        user_id, username, permissions = _resolve_user_from_api_key(auth)
    return user_id, username, permissions


def authenticate_socket(f):
    """Decorator to authenticate the WebSocket ``connect`` handshake.

    SECURITY: Rejects unauthenticated connections instead of allowing them
    as anonymous. A valid Flask session or API key is required, and the
    caller must additionally hold ``_SOCKET_MIN_PERMISSION`` -- otherwise a
    narrowly-scoped credential (e.g. an API key minted only for
    ``read:settings``) would receive every certificate and CA broadcast.

    Only the ``connect`` event carries the socket.io ``auth`` payload, so this
    decorator belongs on ``connect`` alone. Post-connect events are guarded by
    ``require_socket_auth``, which reuses the identity established here.
    This patch has been sponsored by PMGA Tech LLP
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = kwargs.get('auth')
        if auth is None and args and isinstance(args[0], dict):
            auth = args[0]

        user_id, username, permissions = _authenticate_handshake(auth)

        if user_id is None:
            logger.warning(
                "WebSocket connection rejected: no authenticated session "
                "(sid=%s, remote=%s)",
                getattr(request, 'sid', '?'),
                request.remote_addr,
            )
            # Reject the connection — SocketIO treats a False return
            # from the connect handler as a refusal.
            return False

        if not _has_socket_permission(permissions):
            logger.warning(
                "WebSocket connection rejected: user %s lacks %s "
                "(sid=%s, remote=%s)",
                user_id,
                _SOCKET_MIN_PERMISSION,
                getattr(request, 'sid', '?'),
                request.remote_addr,
            )
            return False

        request.user_id = user_id
        request.username = username
        request.permissions = permissions

        return f(*args, **kwargs)

    return decorated


def _has_socket_permission(permissions) -> bool:
    """True when *permissions* is sufficient to hold a socket."""
    try:
        from auth.unified import has_permission
        return has_permission(_SOCKET_MIN_PERMISSION, permissions or [])
    except Exception as e:
        # Fail closed — an unavailable permission backend must not grant access.
        logger.warning(f"WebSocket permission check failed: {e}")
        return False


def _is_privileged(user_id, permissions) -> bool:
    """True when the caller may subscribe to broad (non-own) rooms.

    Resolved from effective permissions rather than the ``role`` string so that
    custom RBAC roles carrying equivalent read scopes are treated the same as
    the built-in admin/operator/auditor roles. Falls back to the role column
    only when permissions are unavailable.
    This patch has been sponsored by PMGA Tech LLP
    """
    try:
        from auth.unified import has_permission
        if permissions and has_permission('read:cas', permissions) and \
                has_permission('read:certificates', permissions):
            return True
    except Exception as e:
        logger.warning(f"WebSocket privilege check failed: {e}")

    user = db_session_get_user(user_id)
    return getattr(user, 'role', None) in ('admin', 'operator', 'auditor')


def require_socket_auth(f):
    """Decorator for post-connect events.

    Identity is established once during ``connect`` and cached per session id,
    so individual events do not re-hit the auth backend (a per-``ping`` API key
    lookup would mean a database round-trip for every keep-alive). An event
    arriving for an unknown sid means the socket was never authenticated, so it
    is refused and the client is disconnected.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        sid = getattr(request, 'sid', None)
        client = connected_clients.get(sid)

        if not client:
            logger.warning(
                "WebSocket event '%s' refused: unauthenticated sid=%s",
                getattr(f, '__name__', '?'),
                sid,
            )
            disconnect()
            return False

        request.user_id = client['user_id']
        request.username = client.get('username')
        request.permissions = client.get('permissions', [])

        return f(*args, **kwargs)

    return decorated


# ================== Socket Event Handlers ==================

@socketio.on('connect')
@authenticate_socket
def handle_connect(auth=None):
    """Handle new WebSocket connection."""
    user_id = getattr(request, 'user_id', None)
    if user_id is None:
        # authenticate_socket returned False — refuse connection
        return False

    sid = request.sid
    permissions = getattr(request, 'permissions', [])

    connected_clients[sid] = {
        'user_id': user_id,
        'username': getattr(request, 'username', None) or str(user_id),
        'permissions': permissions,
        'is_privileged': _is_privileged(user_id, permissions),
        'connected_at': utc_now().isoformat(),
        'rooms': ['global']
    }

    # Join global room for broadcasts
    join_room('global')

    # Join user-specific room
    join_room(f'user:{user_id}')

    logger.info(f"WebSocket connected: user={user_id}, sid={sid}")

    # Send connection confirmation
    emit('connected', {
        'status': 'ok',
        'user_id': user_id,
        'timestamp': utc_now().isoformat()
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    sid = request.sid
    client = connected_clients.pop(sid, None)

    if client:
        logger.info(f"WebSocket disconnected: user={client.get('user_id')}, sid={sid}")
    else:
        logger.info(f"WebSocket disconnected: sid={sid}")


@socketio.on('subscribe')
@require_socket_auth
def handle_subscribe(data):
    """Subscribe to specific event rooms.

    SECURITY: Validates that the user has permission to subscribe to the
    requested room. Users can only subscribe to their own user room and
    to CA/cert rooms they have read access to. Admins/operators can
    subscribe to any room.
    This patch has been sponsored by PMGA Tech LLP
    """
    user_id = request.user_id
    sid = request.sid

    if not isinstance(data, dict):
        emit('subscribed', {'rooms': []})
        return

    rooms = data.get('rooms') or []
    if not isinstance(rooms, list):
        emit('subscribed', {'rooms': []})
        return

    # Privilege was resolved once at connect time.
    client = connected_clients.get(sid, {})
    is_privileged = client.get('is_privileged', False)
    joined = []

    for room in rooms:
        if not isinstance(room, str):
            continue

        # Validate room name format (prevent injection)
        if not room.startswith(('ca:', 'cert:', 'user:', 'group:')):
            continue

        # Authorization: users can only subscribe to their own user room
        if room.startswith('user:'):
            room_user_id = room[5:]
            if str(user_id) != room_user_id and not is_privileged:
                logger.warning(
                    "WebSocket subscribe denied: user %s attempted to "
                    "subscribe to room %s (sid=%s)",
                    user_id, room, sid,
                )
                continue

        # For CA/cert/group rooms, require read permissions
        # (admins/operators/auditors have broad read access; viewers
        # are restricted to their own resources)
        if room.startswith(('ca:', 'cert:', 'group:')) and not is_privileged:
            logger.warning(
                "WebSocket subscribe denied: unprivileged user %s attempted "
                "to subscribe to room %s (sid=%s)",
                user_id, room, sid,
            )
            continue

        join_room(room)
        joined.append(room)
        if sid in connected_clients:
            connected_clients[sid]['rooms'].append(room)
        logger.debug(f"Client {sid} subscribed to room: {room}")

    # Report only the rooms actually joined, so a client is never told it is
    # listening to a room the server denied.
    emit('subscribed', {'rooms': joined})


@socketio.on('unsubscribe')
@require_socket_auth
def handle_unsubscribe(data):
    """Unsubscribe from specific event rooms."""
    sid = request.sid

    if not isinstance(data, dict):
        emit('unsubscribed', {'rooms': []})
        return

    rooms = data.get('rooms') or []
    if not isinstance(rooms, list):
        emit('unsubscribed', {'rooms': []})
        return

    left = []
    for room in rooms:
        if not isinstance(room, str):
            continue
        leave_room(room)
        left.append(room)
        if sid in connected_clients and room in connected_clients[sid]['rooms']:
            connected_clients[sid]['rooms'].remove(room)

    emit('unsubscribed', {'rooms': left})


@socketio.on('ping')
@require_socket_auth
def handle_ping():
    """Handle ping for connection keep-alive."""
    emit('pong', {'timestamp': utc_now().isoformat()})


# ================== Event Emitter Functions ==================

def emit_event(
    event_type: EventType,
    data: Dict[str, Any],
    room: Optional[str] = None,
    broadcast: bool = True,
    include_self: bool = True
):
    """
    Emit a WebSocket event to connected clients.

    Args:
        event_type: The type of event from EventType enum
        data: Event payload data
        room: Specific room to emit to (default: global)
        broadcast: Whether to broadcast to all clients
        include_self: Whether to include the sender
    """
    payload = {
        'type': event_type.value if isinstance(event_type, EventType) else event_type,
        'data': data,
        'timestamp': utc_now().isoformat()
    }

    target_room = room or 'global'

    try:
        socketio.emit(
            'event',
            payload,
            room=target_room,
            include_self=include_self
        )
        logger.debug(f"Emitted {event_type} to room {target_room}")
    except Exception as e:
        logger.error(f"Failed to emit WebSocket event: {e}")


def emit_to_user(user_id: str, event_type: EventType, data: Dict[str, Any]):
    """Emit event to a specific user."""
    emit_event(event_type, data, room=f'user:{user_id}')


def emit_certificate_event(event_type: EventType, cert_data: Dict[str, Any]):
    """Emit certificate-related event."""
    emit_event(event_type, cert_data, room='global')

    # Also emit to CA-specific room if ca_id present
    if 'ca_id' in cert_data:
        emit_event(event_type, cert_data, room=f'ca:{cert_data["ca_id"]}')


def emit_ca_event(event_type: EventType, ca_data: Dict[str, Any]):
    """Emit CA-related event."""
    emit_event(event_type, ca_data, room='global')


def emit_system_alert(alert_type: str, message: str, severity: str = 'info', details: Optional[Dict] = None):
    """Emit system alert to all connected clients."""
    emit_event(
        EventType.SYSTEM_ALERT,
        {
            'alert_type': alert_type,
            'message': message,
            'severity': severity,  # info, warning, error, critical
            'details': details or {}
        },
        room='global'
    )


def emit_audit_critical(action: str, user: str, resource: str, details: Optional[Dict] = None):
    """Emit critical audit event."""
    emit_event(
        EventType.AUDIT_CRITICAL,
        {
            'action': action,
            'user': user,
            'resource': resource,
            'details': details or {}
        },
        room='global'
    )


# ================== Stats & Management ==================

def get_connected_clients_count() -> int:
    """Get count of connected WebSocket clients."""
    return len(connected_clients)


def get_connected_clients_info() -> Dict[str, Any]:
    """Get information about connected clients."""
    return {
        'count': len(connected_clients),
        'clients': [
            {
                'sid': sid,
                'user_id': info['user_id'],
                'connected_at': info['connected_at'],
                'rooms': info['rooms']
            }
            for sid, info in connected_clients.items()
        ]
    }


def broadcast_to_all(event_type: EventType, data: Dict[str, Any]):
    """Broadcast event to all connected clients."""
    emit_event(event_type, data, room='global', broadcast=True)


# ---------------------------------------------------------------------------
# Helper — lazy DB import to avoid circulars at module load time
# ---------------------------------------------------------------------------

def db_session_get_user(user_id):
    """Fetch a User by ID without importing models at module scope.

    Returns ``None`` for a non-integer id or when the lookup fails, so callers
    can treat an unresolvable user as unprivileged.
    """
    if not isinstance(user_id, int):
        return None
    try:
        from models import db, User
        return db.session.get(User, user_id)
    except Exception as e:
        logger.warning(f"WebSocket user lookup failed for {user_id}: {e}")
        return None
