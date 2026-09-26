# ─────────────────────────────────────────────────────────────────────────────
# api/views.py — Authentication Gauntlet Lab
#
# Wrap-Up Comparison Table (Reporter fills this in at the end of the lab):
#
# +-------------------+------------+-----------+-------------------+----------+
# | Method            | Stateful?  | DB Lookup?| Credentials sent  | Safe on  |
# |                   |            |           | every request?    | HTTP?    |
# +-------------------+------------+-----------+-------------------+----------+
# | Basic Auth        |     No       |       No    |            Yes       |   No       |
# | Session Auth      |      Yes      |    Yes       |   No                |     No     |
# | Opaque Token Auth |       No     |    No       |    Yes               |    No      |
# | JWT               |      No      |      No     |      Yes             |     No     |
# +-------------------+------------+-----------+-------------------+----------+
#
# ─────────────────────────────────────────────────────────────────────────────

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import (
    BasicAuthentication,
    SessionAuthentication,
    TokenAuthentication,
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Basic Authentication
# ─────────────────────────────────────────────────────────────────────────────


@api_view(["GET"])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def basic_auth_view(request):
    # Extract and print the header
    auth_header = request.META.get("HTTP_AUTHORIZATION")
    print(f"Incoming Header: {auth_header}")

    # Reporter — Phase 1 challenge answers:
    # Q1 answer (format of decoded Base64 string):
    # The decoded string format is "username:password" (for admin:admin123, it decodes directly to "admin:admin123").
    #
    # Q2 answer (security over HTTP vs HTTPS):
    # Base64 is just a formatting style (like Morse code), not a secret code or lock. Because HTTP is unencrypted, anyone watching the network can capture the header and easily read the password.

    return Response({"message": "Check your terminal!"})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Session Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
def session_auth_view(request):
    # Reporter — Phase 2 challenge answers:
    # Q1 answer (effect of deleting the session cookie):
    # The browser is logged out because it no longer sends the sessionid cookie; the matching session record can
    # still remain in Django's server-side session database until it expires or is invalidated.
    # Synthesis answer (session hijacking):
    # Restoring the copied sessionid cookie restores access while its server-side session remains valid. An attacker
    # who steals that cookie can impersonate the user without knowing the password; this is session hijacking.

    return Response({"message": "Session authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Token Authentication (Opaque)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def token_auth_view(request):
    # Reporter — Phase 3 challenge answers:
    # Q1 answer (status code when token is tampered):
    # A tampered or invalid opaque token returns HTTP 401 Unauthorized.
    # Q2 answer (algorithm used to hash admin's password in the DB):
    # The password starts with the pbkdf2_sha256 algorithm prefix; Django stores a salted hash instead of admin123 as plaintext.
    # Synthesis answer (how to revoke a token):
    # An administrator must delete the stolen token from the database, which permanently invalidates it for future requests.
    # A JWT is not normally stored in that token table, so it cannot be revoked the same way; it must expire, or a blacklist/
    # server-side denylist must be added to track revoked JWTs.

    return Response({"message": "Token authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — JSON Web Tokens (JWT)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def jwt_protected_view(request):
    # Team Challenge:
# Besides exp, the JWT payload also includes user_id — that's the identifying field baked in alongside the expiry.
# The server validates the token without a DB lookup by recomputing the signature from the header+payload using its secret key and comparing it to the token's signature; if they match, it trusts the payload.

# Synthesis Challenge:
# Tampering with user_id and re-sending returns 401 Unauthorized.
# Even though the tampered token is still well-formed JSON/base64, editing the payload invalidates the signature, since the signature was computed over the original header+payload with the server's secret key. On verification the server recomputes the signature and it no longer matches, so the token is rejected regardless of how valid the JSON inside looks.

    return Response({"message": "JWT authenticated.", "user": request.user.username})
