"""
active_validator/session_validator.py
───────────────────────────────────────
Validation active des sessions côté serveur.
Teste : invalidation après logout, timeout de session, fixation de session.
"""

import httpx
import asyncio
import json
from typing import Dict, Any, Optional


class SessionValidator:
    """
    Valide le comportement des sessions côté serveur via de vraies requêtes HTTP.
    """

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def test_session_invalidation(
        self,
        login_url: str,
        logout_url: str,
        protected_url: str,
        credentials: dict,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO COMPLET : Login → Accès protégé → Logout → Accès protégé (doit échouer).

        Args:
            credentials: {"username": "...", "password": "..."}

        Returns:
            Evidence avec session_invalidated, steps détaillés
        """
        evidence = {
            "attack_type": "SESSION_INVALIDATION",
            "vulnerability_confirmed": False,
            "session_invalidated": False,
            "steps": [],
            "proof": []
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Étape 1: POST /login → récupérer le cookie/token de session
                evidence["steps"].append("Step 1: Attempting login...")
                login_response = await client.post(
                    login_url,
                    data=credentials
                )

                evidence["steps"].append(f"Login response: {login_response.status_code}")

                if login_response.status_code != 200:
                    evidence["proof"].append("Login failed - cannot test session invalidation")
                    return evidence

                # Extraire les cookies/tokens de session
                session_cookies = dict(login_response.cookies)
                session_token = login_response.headers.get("Authorization", "")

                if not session_cookies and not session_token:
                    evidence["proof"].append("No session cookie or token found after login")
                    return evidence

                evidence["steps"].append(f"Session established. Cookies: {list(session_cookies.keys())}, Token: {bool(session_token)}")

                # Étape 2: GET /protected → vérifier que la session fonctionne
                evidence["steps"].append("Step 2: Testing protected access before logout...")
                protected_response_before = await client.get(
                    protected_url,
                    cookies=session_cookies,
                    headers={"Authorization": session_token} if session_token else None
                )

                evidence["steps"].append(f"Protected access before logout: {protected_response_before.status_code}")

                if protected_response_before.status_code not in [200, 201]:
                    evidence["proof"].append("Session not working - cannot test invalidation")
                    return evidence

                # Étape 3: POST /logout
                evidence["steps"].append("Step 3: Attempting logout...")
                logout_response = await client.post(
                    logout_url,
                    cookies=session_cookies,
                    headers={"Authorization": session_token} if session_token else None
                )

                evidence["steps"].append(f"Logout response: {logout_response.status_code}")

                # Étape 4: GET /protected avec la même session → doit être 401/403
                evidence["steps"].append("Step 4: Testing protected access after logout...")
                protected_response_after = await client.get(
                    protected_url,
                    cookies=session_cookies,
                    headers={"Authorization": session_token} if session_token else None
                )

                evidence["steps"].append(f"Protected access after logout: {protected_response_after.status_code}")

                # Vérifier si la session a été invalidée
                if protected_response_after.status_code in [401, 403]:
                    evidence["session_invalidated"] = True
                    evidence["proof"].append(
                        f"Session properly invalidated. After logout: {protected_response_after.status_code}"
                    )
                else:
                    evidence["vulnerability_confirmed"] = True
                    evidence["proof"].append(
                        f"VULNERABILITY: Session NOT invalidated! After logout still got: {protected_response_after.status_code}"
                    )

        except Exception as e:
            evidence["proof"].append(f"Test failed: {str(e)}")

        return evidence

    async def test_session_fixation(
        self,
        login_url: str,
        protected_url: str,
        credentials: dict,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Session fixation.
        Vérifier que l'ID de session change après le login (il doit changer).

        Returns:
            Evidence avec session_id_before, session_id_after, vulnerability_confirmed
        """
        evidence = {
            "attack_type": "SESSION_FIXATION",
            "vulnerability_confirmed": False,
            "session_id_before": None,
            "session_id_after": None,
            "session_changed": False,
            "proof": []
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Étape 1: GET /login page → noter le session cookie
                evidence["steps"] = ["Step 1: Getting initial session cookie..."]
                initial_response = await client.get(login_url)

                # Extraire le cookie de session initial
                session_id_before = None
                for cookie_name, cookie_value in initial_response.cookies.items():
                    if 'session' in cookie_name.lower() or 'jsession' in cookie_name.lower():
                        session_id_before = cookie_value
                        break

                if not session_id_before:
                    evidence["proof"].append("No session cookie found on login page")
                    return evidence

                evidence["session_id_before"] = session_id_before
                evidence["steps"].append(f"Initial session ID: {session_id_before[:20]}...")

                # Étape 2: POST /login avec ce cookie
                evidence["steps"].append("Step 2: Logging in with initial session...")
                login_response = await client.post(
                    login_url,
                    data=credentials,
                    cookies=initial_response.cookies
                )

                evidence["steps"].append(f"Login response: {login_response.status_code}")

                if login_response.status_code not in [200, 201]:
                    evidence["proof"].append("Login failed - cannot test session fixation")
                    return evidence

                # Extraire le nouveau cookie de session
                session_id_after = None
                for cookie_name, cookie_value in login_response.cookies.items():
                    if 'session' in cookie_name.lower() or 'jsession' in cookie_name.lower():
                        session_id_after = cookie_value
                        break

                if not session_id_after:
                    evidence["proof"].append("No session cookie found after login")
                    return evidence

                evidence["session_id_after"] = session_id_after
                evidence["steps"].append(f"Session ID after login: {session_id_after[:20]}...")

                # Vérifier que le cookie a changé après login
                if session_id_before != session_id_after:
                    evidence["session_changed"] = True
                    evidence["proof"].append(
                        "Session ID changed after login - no fixation vulnerability"
                    )
                else:
                    evidence["vulnerability_confirmed"] = True
                    evidence["proof"].append(
                        "VULNERABILITY: Session ID did NOT change after login - Session Fixation!"
                    )

                # Test optionnel: vérifier que l'ancienne session ne fonctionne plus
                if session_id_before != session_id_after:
                    evidence["steps"].append("Step 3: Testing if old session still works...")
                    test_response = await client.get(
                        protected_url,
                        cookies={list(initial_response.cookies.keys())[0]: session_id_before}
                    )
                    evidence["steps"].append(f"Old session test: {test_response.status_code}")

        except Exception as e:
            evidence["proof"].append(f"Test failed: {str(e)}")

        return evidence

    async def test_concurrent_sessions(
        self,
        login_url: str,
        protected_url: str,
        credentials: dict,
        session_count: int = 3,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Sessions parallèles non limitées.
        Ouvrir N sessions simultanées et vérifier si le serveur les accepte toutes.

        Returns:
            Evidence avec sessions_allowed, vulnerability_confirmed si > 1 session active
        """
        evidence = {
            "attack_type": "CONCURRENT_SESSIONS",
            "vulnerability_confirmed": False,
            "sessions_attempted": session_count,
            "sessions_successful": 0,
            "sessions_allowed": False,
            "proof": []
        }

        async def create_and_test_session(session_num: int) -> Dict[str, Any]:
            """Crée et teste une session individuelle."""
            session_result = {
                "session_num": session_num,
                "successful": False,
                "status_code": None,
                "error": None
            }

            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    # Créer une nouvelle session
                    login_response = await client.post(login_url, data=credentials)

                    if login_response.status_code not in [200, 201]:
                        session_result["error"] = f"Login failed: {login_response.status_code}"
                        return session_result

                    # Tester l'accès protégé
                    protected_response = await client.get(
                        protected_url,
                        cookies=dict(login_response.cookies)
                    )

                    session_result["status_code"] = protected_response.status_code
                    session_result["successful"] = protected_response.status_code in [200, 201]

                    return session_result

            except Exception as e:
                session_result["error"] = str(e)
                return session_result

        try:
            # Créer session_count sessions en parallèle avec asyncio.gather
            evidence["steps"] = [f"Creating {session_count} concurrent sessions..."]

            # Créer toutes les sessions en parallèle
            session_tasks = [
                create_and_test_session(i + 1)
                for i in range(session_count)
            ]

            session_results = await asyncio.gather(*session_tasks)

            # Analyser les résultats
            successful_sessions = [
                result for result in session_results
                if result["successful"]
            ]

            evidence["sessions_successful"] = len(successful_sessions)

            # Vérifier que toutes les sessions fonctionnent simultanément
            if len(successful_sessions) > 1:
                evidence["sessions_allowed"] = True
                evidence["proof"].append(
                    f"Multiple concurrent sessions allowed: {len(successful_sessions)}/{session_count}"
                )

                # Si plus de 2 sessions fonctionnent, c'est potentiellement une vulnérabilité
                if len(successful_sessions) >= 2:
                    evidence["vulnerability_confirmed"] = True
                    evidence["proof"].append(
                        "VULNERABILITY: Server allows multiple concurrent sessions without limit"
                    )

            # Détails des sessions
            evidence["session_details"] = []
            for result in session_results:
                detail = {
                    "session": result["session_num"],
                    "successful": result["successful"],
                    "status": result["status_code"]
                }
                if result["error"]:
                    detail["error"] = result["error"]
                evidence["session_details"].append(detail)

        except Exception as e:
            evidence["proof"].append(f"Test failed: {str(e)}")

        return evidence

    async def test_session_timeout(
        self,
        protected_url: str,
        token: str,
        wait_seconds: int = 0,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Absence de timeout de session.
        Note : On ne peut pas attendre longtemps, mais on peut vérifier l'expiration du JWT.

        Returns:
            Evidence avec timeout_enforced
        """
        evidence = {
            "attack_type": "SESSION_TIMEOUT",
            "vulnerability_confirmed": False,
            "timeout_enforced": False,
            "token_expiry": None,
            "token_lifetime_hours": None,
            "excessive_lifetime": False,
            "proof": []
        }

        try:
            import jwt
            import base64
            from datetime import datetime

            # Vérifier si le JWT a un exp
            try:
                parts = token.split('.')
                if len(parts) >= 2:
                    payload = json.loads(
                        base64.urlsafe_b64decode(parts[1] + "==").decode()
                    )

                    # Si exp présent, calculer la durée de validité
                    if 'exp' in payload:
                        exp_timestamp = payload['exp']
                        exp_datetime = datetime.fromtimestamp(exp_timestamp)

                        evidence["token_expiry"] = exp_datetime.isoformat()

                        # Calculer la durée de vie du token
                        iat_timestamp = payload.get('iat', exp_timestamp - 3600)  # Default 1 hour if not specified
                        iat_datetime = datetime.fromtimestamp(iat_timestamp)

                        token_lifetime_seconds = exp_timestamp - iat_timestamp
                        token_lifetime_hours = token_lifetime_seconds / 3600

                        evidence["token_lifetime_hours"] = round(token_lifetime_hours, 2)

                        # Signaler si la durée est > 24h (excessive)
                        if token_lifetime_hours > 24:
                            evidence["excessive_lifetime"] = True
                            evidence["vulnerability_confirmed"] = True
                            evidence["timeout_enforced"] = False
                            evidence["proof"].append(
                                f"VULNERABILITY: Excessive token lifetime: {token_lifetime_hours:.2f} hours (> 24h)"
                            )
                        else:
                            evidence["timeout_enforced"] = True
                            evidence["proof"].append(
                                f"Token lifetime is reasonable: {token_lifetime_hours:.2f} hours"
                            )
                    else:
                        evidence["proof"].append("JWT does not have expiration claim (exp)")
                        evidence["vulnerability_confirmed"] = True
                        evidence["timeout_enforced"] = False

                    # Vérifier d'autres claims liés au temps
                    if 'nbf' in payload:
                        nbf_datetime = datetime.fromtimestamp(payload['nbf'])
                        evidence["not_before"] = nbf_datetime.isoformat()

                    if 'iat' in payload:
                        iat_datetime = datetime.fromtimestamp(payload['iat'])
                        evidence["issued_at"] = iat_datetime.isoformat()

                else:
                    evidence["proof"].append("Invalid JWT format")

            except jwt.InvalidTokenError as e:
                evidence["proof"].append(f"Invalid JWT token: {str(e)}")
            except Exception as e:
                evidence["proof"].append(f"Error analyzing token: {str(e)}")

            # Test optionnel: attendre et tester si le token est encore valide
            if wait_seconds > 0:
                evidence["steps"] = [f"Waiting {wait_seconds} seconds before testing token..."]
                await asyncio.sleep(wait_seconds)

                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    test_response = await client.get(
                        protected_url,
                        headers={"Authorization": f"Bearer {token}"}
                    )

                    evidence["test_after_wait"] = {
                        "status_code": test_response.status_code,
                        "still_valid": test_response.status_code in [200, 201]
                    }

                    if test_response.status_code in [401, 403]:
                        evidence["timeout_enforced"] = True
                        evidence["proof"].append("Token properly expired after wait period")

        except Exception as e:
            evidence["proof"].append(f"Test failed: {str(e)}")

        return evidence
