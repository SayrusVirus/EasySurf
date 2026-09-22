from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class OfferwallGGError(Exception):
    pass


class OfferwallGG:
    """
    Offerwall.GG publisher API adapter.

    Current official API model:
      - public placement key: appId
      - secret authentication: X-Api-Key
      - offers endpoint: /api/v1/offers
      - conversion confirmation: signed server-to-server postback

    This module does NOT:
      - create fake offers
      - credit user balances
      - modify the EasySurf database
      - treat a click as a conversion
    """

    API_BASE = os.getenv(
        "OFFERWALL_GG_API_BASE",
        "https://offerwall.gg",
    ).rstrip("/")

    PUBLIC_KEY = os.getenv(
        "OFFERWALL_GG_PUBLIC_KEY",
        "",
    ).strip()

    SECRET_KEY = os.getenv(
        "OFFERWALL_GG_SECRET_KEY",
        "",
    ).strip()

    TIMEOUT = int(
        os.getenv(
            "OFFERWALL_GG_TIMEOUT",
            "20",
        )
    )

    @classmethod
    def configured(cls) -> bool:
        return bool(
            cls.PUBLIC_KEY and
            cls.SECRET_KEY
        )

    @classmethod
    def status(cls) -> dict[str, Any]:
        return {
            "provider": "Offerwall.GG",
            "configured": cls.configured(),
            "public_key_present": bool(cls.PUBLIC_KEY),
            "secret_key_present": bool(cls.SECRET_KEY),
            "api_base": cls.API_BASE,
            "offers_endpoint": "/api/v1/offers",
        }

    @classmethod
    def _headers(cls) -> dict[str, str]:
        if not cls.SECRET_KEY:
            raise OfferwallGGError(
                "OFFERWALL_GG_SECRET_KEY is not configured"
            )

        return {
            "Accept": "application/json",
            "X-Api-Key": cls.SECRET_KEY,
            "User-Agent": "EasySurf/1.0",
        }

    @classmethod
    def get_offers(
        cls,
        user_id: int | str,
        **extra_params: Any,
    ) -> Any:
        """
        Fetch the offers available to one EasySurf user.

        The provider documentation states that userId is used for
        targeting and that the response contains a ready-to-use
        clickUrl.

        This method requires real provider credentials.
        """

        if not cls.configured():
            raise OfferwallGGError(
                "Offerwall.GG credentials are not configured"
            )

        params = {
            "appId": cls.PUBLIC_KEY,
            "userId": str(user_id),
        }

        for key, value in extra_params.items():
            if value is not None:
                params[key] = value

        query = urlencode(params)

        url = (
            cls.API_BASE +
            "/api/v1/offers?" +
            query
        )

        request = Request(
            url=url,
            headers=cls._headers(),
            method="GET",
        )

        try:
            with urlopen(
                request,
                timeout=cls.TIMEOUT,
            ) as response:

                raw = response.read()

                content_type = (
                    response.headers
                    .get("Content-Type", "")
                    .lower()
                )

        except HTTPError as exc:
            try:
                body = exc.read().decode(
                    "utf-8",
                    errors="replace",
                )
            except Exception:
                body = ""

            raise OfferwallGGError(
                f"Offerwall.GG HTTP {exc.code}: "
                f"{body[:500]}"
            ) from exc

        except URLError as exc:
            raise OfferwallGGError(
                f"Offerwall.GG connection error: {exc}"
            ) from exc

        except TimeoutError as exc:
            raise OfferwallGGError(
                "Offerwall.GG request timed out"
            ) from exc

        text = raw.decode(
            "utf-8",
            errors="replace",
        )

        if "application/json" not in content_type:
            raise OfferwallGGError(
                "Offerwall.GG returned a non-JSON response"
            )

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise OfferwallGGError(
                "Offerwall.GG returned invalid JSON"
            ) from exc

    @classmethod
    def verify_postback_signature(
        cls,
        user_id: str,
        transaction_id: str,
        currency_amount: str,
        signature: str,
    ) -> bool:
        """
        Verify the official Offerwall.GG callback signature.

        Signature input is exactly:

            userId:transactionId:currencyAmount

        using HMAC-SHA256 and the placement secret key.
        """

        if not cls.SECRET_KEY:
            return False

        message = (
            f"{user_id}:"
            f"{transaction_id}:"
            f"{currency_amount}"
        )

        expected = hmac.new(
            cls.SECRET_KEY.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(
            expected,
            str(signature or "").strip(),
        )

    @classmethod
    def build_wall_url(
        cls,
        user_id: int | str,
    ) -> str:
        """
        Build the official hosted-wall URL.

        The public key is safe to expose in the URL.
        """

        if not cls.PUBLIC_KEY:
            raise OfferwallGGError(
                "OFFERWALL_GG_PUBLIC_KEY is not configured"
            )

        return (
            f"{cls.API_BASE}/wall/"
            f"{cls.PUBLIC_KEY}?"
            + urlencode({
                "userId": str(user_id),
            })
        )


def provider_status() -> dict[str, Any]:
    return OfferwallGG.status()
