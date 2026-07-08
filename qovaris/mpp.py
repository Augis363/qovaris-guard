"""
Nexus Guard — Stripe Machine Payments Protocol (MPP) Integration
=================================================================

`MPP <https://mpp.dev/>`_ is the open ``Payment`` HTTP authentication scheme
(``draft-ryan-httpauth-payment``, co-authored by Stripe and Tempo) that
standardises **HTTP 402 Payment Required** so autonomous agents can pay for any
HTTP-addressable resource — REST APIs, MCP servers, web pages — in the same
request.  It is x402-compatible.

The flow is **Challenge → Credential → Receipt**:

1. The agent requests a resource.
2. The server replies ``402 Payment Required`` with a
   ``WWW-Authenticate: Payment ...`` challenge describing what the resource
   costs (``method``, ``intent``, ``expires``, and a base64url-JCS-encoded
   ``request`` blob carrying ``amount`` / ``currency`` / ``recipient``).
3. The agent authorises payment and retries with an
   ``Authorization: Payment ...`` credential.
4. On success the server returns a ``Payment-Receipt`` header.

**Where Nexus fits:** a malicious or hallucinating agent will happily pay any
402 challenge it encounters — that is exactly the "purchase intent" attack
surface.  :class:`MPPGuard` parses the challenge and runs it through the same
firewall used for every other tool call **before** the agent is allowed to
authorise payment.  Budget caps, MCC blocks, and HITL all apply.

This module is **stdlib-only**.  It does not perform settlement itself — you
supply a ``payer`` callable that produces the credential once Nexus approves.

Example
-------
::

    from nexus_guard import NexusFinOpsGuard
    from nexus_guard.mpp import MPPGuard

    guard = NexusFinOpsGuard(mode="embedded", spend_threshold=50)
    mpp = MPPGuard(guard)

    challenge = response.headers["WWW-Authenticate"]   # from a 402 response
    with guard.session("Fetch one weather report, max $1"):
        decision = mpp.authorize_challenge(challenge)   # raises if blocked
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from .guard import NexusFinOpsGuard, SecurityBlockException

__all__ = [
    "PaymentChallenge",
    "MPPGuard",
    "parse_payment_challenge",
    "MPPChallengeError",
]


# Minor-unit decimals per currency. MPP amounts are integer strings in the
# currency's smallest unit (e.g. "1000" usd == $10.00; usdc/usdt use 6).
_MINOR_UNIT_DECIMALS: Dict[str, int] = {
    "usd": 2, "eur": 2, "gbp": 2, "cad": 2, "aud": 2, "jpy": 0,
    "usdc": 6, "usdt": 6, "dai": 18, "eth": 18, "sol": 9, "btc": 8,
}

# Matches one ``key="value"`` or ``key=token`` auth-param.
_AUTH_PARAM_RE = re.compile(
    r'(?P<key>[a-zA-Z0-9_\-]+)\s*=\s*(?:"(?P<qval>[^"]*)"|(?P<tval>[^,\s]+))'
)


class MPPChallengeError(ValueError):
    """Raised when a ``WWW-Authenticate: Payment`` header cannot be parsed."""


def _b64url_decode_json(value: str) -> Dict[str, Any]:
    """Decode a base64url (padding-optional) JCS-JSON string into a dict."""
    if not value:
        return {}
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise MPPChallengeError(f"Invalid base64url/JSON in challenge: {exc}") from exc
    if not isinstance(decoded, dict):
        raise MPPChallengeError("Decoded challenge payload is not a JSON object")
    return decoded


@dataclass
class PaymentChallenge:
    """A parsed MPP ``Payment`` challenge from a ``402`` response.

    Attributes
    ----------
    id, realm, method, intent, expires, opaque :
        Raw auth-param values from the ``WWW-Authenticate`` header.
    request :
        Decoded ``request`` blob (``amount`` / ``currency`` / ``recipient`` …).
    amount_minor :
        The raw integer amount in the currency's smallest unit, if present.
    amount :
        ``amount_minor`` converted to major units (e.g. dollars) using
        :data:`_MINOR_UNIT_DECIMALS`.  This is what the firewall compares
        against budget caps.
    currency, recipient :
        Convenience accessors pulled from ``request``.
    params :
        All raw auth-params, for forward-compatibility.
    """

    id: str = ""
    realm: str = ""
    method: str = ""
    intent: str = ""
    expires: str = ""
    opaque: str = ""
    request: Dict[str, Any] = field(default_factory=dict)
    amount_minor: Optional[int] = None
    amount: Optional[float] = None
    currency: Optional[str] = None
    recipient: Optional[str] = None
    params: Dict[str, str] = field(default_factory=dict)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Return ``True`` if the challenge ``expires`` timestamp is in the past."""
        if not self.expires:
            return False
        now = now or datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(self.expires.replace("Z", "+00:00"))
        except ValueError:
            return False
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp < now

    def to_arguments(self) -> Dict[str, Any]:
        """Build the firewall ``arguments`` dict for this payment."""
        return {
            "amount_usd": self.amount,
            "currency": self.currency,
            "recipient": self.recipient,
            "merchant_category": self.request.get("merchant_category", ""),
            "mcc_code": str(self.request.get("mcc_code", "")),
            "method": self.method,
            "realm": self.realm,
        }


def parse_payment_challenge(header_value: str) -> PaymentChallenge:
    """Parse a ``WWW-Authenticate: Payment ...`` header into a
    :class:`PaymentChallenge`.

    Raises :class:`MPPChallengeError` if the header is not a ``Payment``
    challenge or is malformed.
    """
    if not header_value or not header_value.strip():
        raise MPPChallengeError("Empty WWW-Authenticate header")

    value = header_value.strip()
    # Strip the auth scheme token ("Payment"). MPP uses the "Payment" scheme.
    scheme, _, rest = value.partition(" ")
    if scheme.lower() != "payment":
        raise MPPChallengeError(
            f"Not an MPP Payment challenge (scheme={scheme!r}); "
            f"expected 'Payment'."
        )

    params: Dict[str, str] = {}
    for m in _AUTH_PARAM_RE.finditer(rest):
        key = m.group("key").lower()
        params[key] = m.group("qval") if m.group("qval") is not None else m.group("tval")

    request = _b64url_decode_json(params.get("request", ""))

    currency = request.get("currency")
    amount_minor: Optional[int] = None
    amount_major: Optional[float] = None
    raw_amount = request.get("amount")
    if raw_amount is not None:
        try:
            amount_minor = int(str(raw_amount))
            decimals = _MINOR_UNIT_DECIMALS.get((currency or "").lower(), 2)
            amount_major = amount_minor / (10 ** decimals)
        except (ValueError, TypeError):
            amount_minor = None

    return PaymentChallenge(
        id=params.get("id", ""),
        realm=params.get("realm", ""),
        method=params.get("method", ""),
        intent=params.get("intent", ""),
        expires=params.get("expires", ""),
        opaque=params.get("opaque", ""),
        request=request,
        amount_minor=amount_minor,
        amount=amount_major,
        currency=currency,
        recipient=request.get("recipient") or request.get("pay_to"),
        params=params,
    )


class MPPGuard:
    """Firewall for Machine Payments Protocol (MPP) purchase intents.

    Wraps a :class:`NexusFinOpsGuard` so that every 402 payment challenge an
    agent encounters is evaluated against the active session intent, budget
    caps, and merchant policy **before** payment is authorised.

    Parameters
    ----------
    guard : NexusFinOpsGuard
        The guard whose policy engine (embedded or remote) and session intent
        drive the decision.
    allowed_intent : str
        Static constraint describing what these machine payments are for.
    reject_expired : bool
        When ``True`` (default) an expired challenge is rejected before any
        policy evaluation.
    """

    def __init__(
        self,
        guard: NexusFinOpsGuard,
        allowed_intent: str = "Authorise machine (MPP) payments within session budget",
        reject_expired: bool = True,
    ) -> None:
        self.guard = guard
        self.allowed_intent = allowed_intent
        self.reject_expired = reject_expired

    def authorize_challenge(
        self,
        challenge: "str | PaymentChallenge",
        original_intent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate an MPP payment challenge against the firewall.

        ``challenge`` may be the raw ``WWW-Authenticate`` header string or an
        already-parsed :class:`PaymentChallenge`.  Returns the firewall
        decision dict on approval; raises :class:`SecurityBlockException` if the
        payment is blocked (or needs human review with no handler configured).
        """
        if isinstance(challenge, str):
            challenge = parse_payment_challenge(challenge)

        if self.reject_expired and challenge.is_expired():
            raise SecurityBlockException(
                f"Blocked MPP payment: challenge {challenge.id or '?'} expired "
                f"at {challenge.expires}."
            )

        intent = original_intent if original_intent is not None else self.guard.current_intent
        payload = {
            "original_intent": intent,
            "tool_name": f"mpp_payment[{challenge.method or 'unknown'}]",
            "arguments": challenge.to_arguments(),
            "allowed_intent": self.allowed_intent,
        }
        return self.guard._authorize(payload, payload["tool_name"])

    def guarded_pay(
        self,
        challenge: "str | PaymentChallenge",
        payer: Callable[[PaymentChallenge], Any],
        original_intent: Optional[str] = None,
    ) -> Any:
        """Authorise then settle an MPP payment.

        Runs :meth:`authorize_challenge`; only if it approves is ``payer``
        invoked to perform settlement (e.g. produce the ``Authorization:
        Payment`` credential and retry the request).  The result of ``payer``
        is returned.  If the firewall blocks the payment, ``payer`` is **never**
        called and :class:`SecurityBlockException` propagates.
        """
        if isinstance(challenge, str):
            challenge = parse_payment_challenge(challenge)
        self.authorize_challenge(challenge, original_intent=original_intent)
        return payer(challenge)
