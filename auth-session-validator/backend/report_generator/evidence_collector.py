"""
report_generator/evidence_collector.py
────────────────────────────────────────
Collecte et formate les preuves d'exploit pour le rapport.
Transforme les résultats bruts en preuves lisibles et vérifiables.
"""

from typing import Dict, Any, List


class EvidenceCollector:
    """
    Agrège et formate les preuves de toutes les phases d'analyse.
    Chaque preuve doit être reproductible et vérifiable.
    """

    def collect_all(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Collecte toutes les preuves disponibles depuis les résultats d'analyse.

        Returns:
            Liste de preuves structurées : [{"type", "severity", "proof_text", "reproduction_steps"}, ...]
        """
        evidences = []
        evidences.extend(self._collect_static_evidence(analysis_results.get("static", {})))
        evidences.extend(self._collect_dynamic_evidence(analysis_results.get("dynamic", {})))
        evidences.extend(self._collect_active_evidence(analysis_results.get("validation", {})))
        evidences.extend(self._collect_correlation_evidence(analysis_results.get("correlations", [])))
        return evidences

    def _collect_static_evidence(self, static: dict) -> List[Dict[str, Any]]:
        """
        Formate les preuves statiques (secrets trouvés dans le code).

        Format de preuve :
        - Fichier source, numéro de ligne
        - Extrait du code (masqué partiellement)
        - Impact potentiel
        """
        evidences = []

        # Pour chaque secret finding, créer une preuve avec:
        #   - fichier:ligne
        #   - extrait du code (token masqué après les 10 premiers chars)
        #   - "reproduction: décompiler l'APK avec jadx et chercher ce pattern"
        findings = static.get("findings", [])

        for finding in findings:
            if finding.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                evidence = {
                    "type": "STATIC_ANALYSIS",
                    "severity": finding.get("severity", "UNKNOWN"),
                    "category": finding.get("type", "UNKNOWN"),
                    "proof_text": "",
                    "reproduction_steps": []
                }

                # Informations sur le fichier
                file_path = finding.get("file", "Unknown file")
                line_number = finding.get("line", "Unknown line")

                # Extrait du code avec masquage
                snippet = finding.get("snippet", "")
                if snippet:
                    masked_snippet = self._mask_sensitive_data(snippet)
                    evidence["proof_text"] = f"File: {file_path}:{line_number}\nCode:\n{masked_snippet}"

                # Description de l'impact
                description = finding.get("description", "")
                if description:
                    evidence["proof_text"] += f"\n\nImpact: {description}"

                # Étapes de reproduction
                evidence["reproduction_steps"] = [
                    f"1. Decompile APK with JADX",
                    f"2. Search for pattern in {file_path}",
                    f"3. Verify finding at line {line_number}"
                ]

                # Référence OWASP
                owasp_ref = finding.get("owasp_ref", "")
                if owasp_ref:
                    evidence["owasp_reference"] = owasp_ref

                evidences.append(evidence)

        return evidences

    def _collect_dynamic_evidence(self, dynamic: dict) -> List[Dict[str, Any]]:
        """
        Formate les preuves dynamiques (trafic intercepté).

        Format de preuve :
        - URL interceptée
        - Headers de la requête (token visible)
        - "reproduction: configurer proxy mitmproxy sur port 8888"
        """
        evidences = []

        # Pour chaque JWT intercepté, créer une preuve avec la requête HTTP
        jwt_tokens = dynamic.get("jwt_tokens", [])
        for token_info in jwt_tokens:
            evidence = {
                "type": "DYNAMIC_ANALYSIS",
                "severity": "HIGH",
                "category": "JWT_INTERCEPTED",
                "proof_text": "",
                "reproduction_steps": []
            }

            # URL interceptée
            url = token_info.get("url", "Unknown URL")
            method = token_info.get("method", "GET")

            # Headers de la requête (token visible)
            headers = token_info.get("headers", {})
            token = token_info.get("token", "")

            if token:
                masked_token = self.mask_token(token, visible_chars=15)
                headers_display = {k: v for k, v in headers.items()}
                if "authorization" in headers_display:
                    headers_display["authorization"] = f"Bearer {masked_token}"

                # Formater la requête HTTP
                http_request = self.format_http_request(
                    method=method,
                    url=url,
                    headers=headers_display
                )
                evidence["proof_text"] = http_request

            # Étapes de reproduction
            evidence["reproduction_steps"] = [
                "1. Configure MITM proxy on port 8080",
                "2. Install CA certificate on device",
                "3. Set device proxy to proxy server",
                f"4. Trigger request to {url}",
                "5. Intercept JWT token in Authorization header"
            ]

            evidences.append(evidence)

        # Pour chaque flux HTTP non chiffré, montrer l'URL et les données exposées
        flows = dynamic.get("flows", [])
        for flow in flows:
            if flow.get("scheme") == "http":  # Non-HTTPS
                evidence = {
                    "type": "DYNAMIC_ANALYSIS",
                    "severity": "CRITICAL",
                    "category": "INSECURE_HTTP",
                    "proof_text": "",
                    "reproduction_steps": []
                }

                url = flow.get("url", "Unknown URL")
                method = flow.get("method", "GET")

                # Données exposées
                request_data = flow.get("request", {})
                response_data = flow.get("response", {})

                evidence["proof_text"] = f"INSECURE HTTP REQUEST:\n"
                evidence["proof_text"] += f"{method} {url}\n\n"

                if request_data:
                    evidence["proof_text"] += "Request Data:\n"
                    for key, value in request_data.items():
                        if key.lower() in ["password", "token", "secret", "key"]:
                            value = self.mask_token(str(value), visible_chars=5)
                        evidence["proof_text"] += f"  {key}: {value}\n"

                # Étapes de reproduction
                evidence["reproduction_steps"] = [
                    "1. Configure network proxy",
                    "2. Monitor HTTP traffic",
                    f"3. Observe unencrypted communication to {url}",
                    "4. Sensitive data is visible in plaintext"
                ]

                evidences.append(evidence)

        return evidences

    def _collect_active_evidence(self, validation: dict) -> List[Dict[str, Any]]:
        """
        Formate les preuves des tests actifs (exploits confirmés).

        Format de preuve :
        - Requête HTTP envoyée (avec token forgé)
        - Réponse HTTP reçue (code + body partiel)
        - Étapes de reproduction
        """
        evidences = []

        # Pour chaque test actif avec vulnerability_confirmed == True
        # construire une preuve avec les steps et les status codes HTTP
        test_results = validation.get("test_results", [])

        for test_result in test_results:
            if test_result.get("vulnerability_confirmed"):
                evidence = {
                    "type": "ACTIVE_VALIDATION",
                    "severity": "CRITICAL",
                    "category": test_result.get("attack_type", "UNKNOWN"),
                    "proof_text": "",
                    "reproduction_steps": []
                }

                # Détails de l'attaque
                attack_type = test_result.get("attack_type", "Unknown attack")
                evidence["proof_text"] = f"CONFIRMED VULNERABILITY: {attack_type}\n\n"

                # Steps de l'attaque
                steps = test_result.get("steps", [])
                if steps:
                    evidence["proof_text"] += "Attack Steps:\n"
                    for i, step in enumerate(steps, 1):
                        evidence["proof_text"] += f"{i}. {step}\n"

                # Preuves spécifiques
                proofs = test_result.get("proof", [])
                if proofs:
                    evidence["proof_text"] += "\nEvidence:\n"
                    for proof in proofs:
                        evidence["proof_text"] += f"- {proof}\n"

                # Détails de la requête/réponse si disponibles
                if "request" in test_result:
                    request = test_result["request"]
                    evidence["proof_text"] += f"\nMalicious Request:\n"
                    evidence["proof_text"] += f"Method: {request.get('method', 'GET')}\n"
                    evidence["proof_text"] += f"URL: {request.get('url', 'Unknown')}\n"

                    headers = request.get("headers", {})
                    if headers:
                        evidence["proof_text"] += "Headers:\n"
                        for key, value in headers.items():
                            if key.lower() in ["authorization", "cookie", "token"]:
                                value = self.mask_token(str(value), visible_chars=10)
                            evidence["proof_text"] += f"  {key}: {value}\n"

                if "response" in test_result:
                    response = test_result["response"]
                    evidence["proof_text"] += f"\nServer Response:\n"
                    evidence["proof_text"] += f"Status: {response.get('status_code', 'Unknown')}\n"

                    body = response.get("body", "")
                    if body:
                        # Masquer les données sensibles dans le body
                        masked_body = self._mask_sensitive_data(str(body))
                        evidence["proof_text"] += f"Body: {masked_body[:200]}...\n"

                # Étapes de reproduction
                evidence["reproduction_steps"] = [
                    f"1. Prepare {attack_type} attack",
                    "2. Execute attack against target endpoint",
                    "3. Observe server response",
                    "4. Confirm vulnerability if response indicates success"
                ]

                # Ajouter les steps spécifiques si disponibles
                if steps:
                    evidence["reproduction_steps"] = [
                        f"Step {i+1}: {step}" for i, step in enumerate(steps)
                    ]

                evidences.append(evidence)

        return evidences

    def _collect_correlation_evidence(self, correlations: list) -> List[Dict[str, Any]]:
        """
        Formate les preuves de corrélation (trouvé statiquement ET dynamiquement).

        Format de preuve :
        - Source statique (fichier)
        - Confirmation dynamique (URL)
        - "Ce token trouvé dans le code est le même que celui intercepté sur le réseau"
        """
        evidences = []

        # Pour chaque corrélation, combiner les preuves statique et dynamique
        for correlation in correlations:
            evidence = {
                "type": "CORRELATION_ANALYSIS",
                "severity": "HIGH",
                "category": correlation.get("type", "UNKNOWN"),
                "proof_text": "",
                "reproduction_steps": []
            }

            # Source statique (fichier)
            static_source = correlation.get("static_source", {})
            if static_source:
                file_path = static_source.get("file", "Unknown file")
                line_number = static_source.get("line", "Unknown line")
                pattern = static_source.get("pattern", "Unknown pattern")

                evidence["proof_text"] = f"STATIC SOURCE:\n"
                evidence["proof_text"] += f"File: {file_path}:{line_number}\n"
                evidence["proof_text"] += f"Pattern: {pattern}\n\n"

            # Confirmation dynamique (URL)
            dynamic_source = correlation.get("dynamic_source", {})
            if dynamic_source:
                url = dynamic_source.get("url", "Unknown URL")
                method = dynamic_source.get("method", "GET")
                intercepted_data = dynamic_source.get("data", {})

                evidence["proof_text"] += f"DYNAMIC CONFIRMATION:\n"
                evidence["proof_text"] += f"URL: {method} {url}\n"

                if intercepted_data:
                    evidence["proof_text"] += f"Intercepted Data:\n"
                    for key, value in intercepted_data.items():
                        if key.lower() in ["token", "password", "secret"]:
                            value = self.mask_token(str(value), visible_chars=8)
                        evidence["proof_text"] += f"  {key}: {value}\n"

            # Corrélation
            evidence["proof_text"] += f"\nCORRELATION:\n"
            evidence["proof_text"] += f"This {correlation.get('type', 'pattern')} found in source code "
            evidence["proof_text"] += f"matches the data intercepted in network traffic.\n"

            # Score de confiance
            confidence = correlation.get("confidence", 0)
            evidence["proof_text"] += f"Confidence Score: {confidence}/100\n"

            # Étapes de reproduction
            evidence["reproduction_steps"] = [
                "1. Perform static analysis to identify sensitive patterns",
                "2. Configure network proxy to intercept traffic",
                "3. Trigger application functionality",
                "4. Correlate static findings with dynamic intercepts",
                "5. Confirm data leakage paths"
            ]

            evidences.append(evidence)

        return evidences

    @staticmethod
    def format_http_request(method: str, url: str, headers: dict, body: str = "") -> str:
        """
        Formate une requête HTTP de manière lisible pour le rapport.

        Returns:
            Chaîne de texte formatée comme une vraie requête HTTP
        """
        # Construire la représentation HTTP/1.1 standard
        # Exemple :
        # POST /api/login HTTP/1.1
        # Host: 10.0.2.2:8888
        # Authorization: Bearer eyJ...
        # Content-Type: application/json
        #
        # {"username": "admin", "password": "password"}

        # Extraire le chemin de l'URL
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        path = parsed_url.path
        if parsed_url.query:
            path += f"?{parsed_url.query}"

        # Construire la ligne de requête
        request_lines = [
            f"{method.upper()} {path} HTTP/1.1"
        ]

        # Ajouter les headers
        if headers:
            # Host header
            if "host" not in [h.lower() for h in headers.keys()]:
                host = parsed_url.netloc
                if host:
                    request_lines.append(f"Host: {host}")

            # Autres headers
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")

        # Ajouter le body si présent
        if body:
            request_lines.append("")  # Ligne vide avant le body
            request_lines.append(body)

        return "\n".join(request_lines)

    @staticmethod
    def mask_token(token: str, visible_chars: int = 20) -> str:
        """
        Masque partiellement un token pour l'affichage dans le rapport.
        Exemple : eyJhbGciOiJIUzI1NiJ9... [MASKED]

        Returns:
            Token partiellement masqué
        """
        # Afficher les N premiers chars + "... [MASKED]"
        if not token:
            return "[EMPTY]"

        if len(token) <= visible_chars:
            return f"{token}... [SHORT]"

        visible_part = token[:visible_chars]
        return f"{visible_part}... [MASKED]"

    def _mask_sensitive_data(self, data: str) -> str:
        """
        Masque les données sensibles dans une chaîne de caractères.

        Args:
            data: Chaîne de caractères pouvant contenir des données sensibles

        Returns:
            Chaîne avec les données sensibles masquées
        """
        if not data:
            return data

        # Patterns à masquer
        sensitive_patterns = [
            (r'["\']?password["\']?\s*[:=]\s*["\']?([^"\']{8,})["\']?', 'password": "***MASKED***"'),
            (r'["\']?token["\']?\s*[:=]\s*["\']?([^"\']{15,})["\']?', 'token": "***MASKED***"'),
            (r'["\']?secret["\']?\s*[:=]\s*["\']?([^"\']{10,})["\']?', 'secret": "***MASKED***"'),
            (r'["\']?api_key["\']?\s*[:=]\s*["\']?([^"\']{15,})["\']?', 'api_key": "***MASKED***"'),
            (r'Bearer\s+([A-Za-z0-9-._~+/]{15,})', 'Bearer ***MASKED***'),
        ]

        import re
        masked_data = data

        for pattern, replacement in sensitive_patterns:
            masked_data = re.sub(pattern, replacement, masked_data, flags=re.IGNORECASE)

        return masked_data
