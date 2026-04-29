"""
backend/main.py - Version JADX (Vraie Décompilation Java)
"""

import os
import uuid
import shutil
import zipfile
import re
import subprocess
import json
import time
import asyncio
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from contextlib import asynccontextmanager

from config import UPLOAD_DIR, ROOT_DIR, JADX_PATH, get_target_server_path
from dynamic_analyzer.proxy_manager import proxy_manager
from dynamic_analyzer.frida_manager import frida_manager
from dynamic_analyzer.setup_manager import setup_manager
from dynamic_analyzer.jwt_interceptor import extract_jwts_from_traffic
from dynamic_analyzer.traffic_capture import parse_captured_traffic

# Nouveaux Modules Correlation & Report
from correlation_engine.ml_analyzer import SessionMLAnalyzer
from correlation_engine.risk_scorer import RiskScorer
from correlation_engine.ai_recommender import AIRecommender
from correlation_engine.token_analyzer import TokenAnalyzer
from correlation_engine.correlator import CorrelationEngine
from correlation_engine.token_lifetime_analyzer import TokenLifetimeAnalyzer
from active_validator.attack_chain import AutoAttackChain
from active_validator.token_rotation_tester import TokenRotationTester
from report_generator.pdf_generator import PDFReportGenerator

# MASVS Compliance Module
from masvs.checklist_generator import ChecklistGenerator
from masvs.auth_type_detector import AuthTypeDetector
from masvs.acceptance_criteria import AcceptanceCriteriaGenerator

# Storage Scanner Module
from static_analyzer.storage_scanner import StorageScanner

ml_analyzer = SessionMLAnalyzer()
risk_scorer = RiskScorer()
ai_recommender = AIRecommender()
token_analyzer = TokenAnalyzer()
token_lifetime_analyzer = TokenLifetimeAnalyzer()
token_rotation_tester = TokenRotationTester(base_url="http://127.0.0.1:8888")
checklist_generator = ChecklistGenerator()
auth_type_detector = AuthTypeDetector()
acceptance_criteria_generator = AcceptanceCriteriaGenerator()
storage_scanner = StorageScanner()

import hashlib

# État de la session et des utilisateurs
SESSION_FILE = os.path.join(ROOT_DIR, "session_data.json")
USERS_FILE = os.path.join(ROOT_DIR, "users_db.json")

def save_session(state):
    try:
        with open(SESSION_FILE, "w") as f:
            json.dump(state, f)
    except: pass

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except: return {}
    # Créer un admin par défaut si le fichier n'existe pas
    default_users = {"admin": hash_password("admin@123")}
    save_users(default_users)
    return default_users

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

def load_session():
    defaults = {
        "package_name": "com.android.insecurebankv2",
        "last_apk": None,
        "static_findings": [],
        "attack_results": [],
        "timeline": [],
        "logged_in_user": None
    }
    try:
        if os.path.exists(SESSION_FILE):
            with open(SESSION_FILE, "r") as f:
                data = json.load(f)
                for k, v in defaults.items():
                    if k not in data: data[k] = v
                return data
    except: pass
    return defaults

session_state = load_session()

# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    print(f"[*] Démarrage serveur. État session : {session_state.get('package_name')}", flush=True)
    if not proxy_manager.is_running:
        asyncio.create_task(proxy_manager.start_async())
        print("[*] Tâche Proxy MITM planifiée sur 8080", flush=True)

    # Si une session APK est déjà là, on lance tout en tâche de fond
    if session_state.get("package_name"):
        print(f"[*] Planification setup automatique pour {session_state['package_name']}...", flush=True)
        asyncio.create_task(trigger_auto_setup_internal())

    yield  # Application runs here

    # Shutdown logic (if needed)
    print("[*] Arrêt du serveur...", flush=True)

app = FastAPI(title="Auth and Session Analyzer API", lifespan=lifespan)

# --- AUTH ENDPOINTS ---
@app.post("/api/auth/register")
async def register(data: dict):
    users = load_users()
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Champs manquants")
    if username in users:
        raise HTTPException(status_code=400, detail="L'utilisateur existe déjà")
    
    users[username] = hash_password(password)
    save_users(users)
    return {"message": "Utilisateur créé avec succès"}

@app.post("/api/auth/login")
async def login(data: dict):
    users = load_users()
    username = data.get("username")
    password = data.get("password")
    
    if username in users and users[username] == hash_password(password):
        session_state["logged_in_user"] = username
        return {"message": "Login réussi", "username": username}
    raise HTTPException(status_code=401, detail="Identifiants incorrects")

@app.get("/api/auth/status")
async def auth_status():
    return {"logged_in": session_state.get("logged_in_user") is not None, "user": session_state.get("logged_in_user")}

@app.post("/api/auth/logout")
async def logout():
    session_state["logged_in_user"] = None
    return {"message": "Déconnexion réussie"}


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/status")
async def get_api_status():
    return {
        "proxy": proxy_manager.is_running,
        "frida": frida_manager._is_running if 'frida_manager' in globals() else False,
        "server_target": True # InsecureBank local
    }

async def get_traffic():
    flows = proxy_manager.get_live_results()
    findings = proxy_manager.get_findings()
    
    # Calcul dynamique du score
    risk_score = 0
    risk_level = "LOW"
    
    for f in findings:
        if f["severity"] == "CRITICAL": risk_score += 40
        elif f["severity"] == "HIGH": risk_score += 20
        elif f["severity"] == "MEDIUM": risk_score += 10
        else: risk_score += 5
        
    if risk_score > 80: risk_level = "CRITICAL"
    elif risk_score > 40: risk_level = "HIGH"
    elif risk_score > 20: risk_level = "MEDIUM"
    
    return {
        "flows": flows,
        "findings": findings,
        "risk_score": f"{min(risk_score, 150)}/150",
        "risk_level": risk_level
    }

@app.get("/api/proxy/traffic")
async def get_proxy_traffic():
    return await get_traffic()

@app.get("/api/session/status")
async def get_session_status():
    data = {
        "last_apk": session_state.get("last_apk"),
        "package_name": session_state.get("package_name"),
        "static_findings": session_state.get("static_findings", []),
        "analysis_id": session_state.get("analysis_id")
    }
    return data

# 📚 IMPACT & STORYTELLING DATABASE
VULN_IMPACT = {
    "JWT_BYPASS": "Un attaquant peut usurper l'identité de n'importe quel utilisateur (dont l'admin) sans connaître son mot de passe.",
    "SESSION_FIXATION": "Un attaquant peut forcer une victime à utiliser une session contrôlée, permettant le vol complet du compte après login.",
    "TOKEN_REPLAY": "Un token intercepté reste valide indéfiniment, même après déconnexion, offrant un accès permanent aux données sensibles.",
    "INSECURE_HTTP": "Toutes les communications (mots de passe, tokens) circulent en clair sur le réseau et peuvent être interceptées (Man-in-the-Middle).",
    "HARDCODED_SECRET": "La clé de signature étant publique, n'importe qui peut forger des tokens d'accès valides pour l'API.",
    "WEAK_CRYPTO": "L'utilisation de modes non sécurisés (ECB) ou d'algorithmes obsolètes (DES) permet à un attaquant de déchiffrer les données sensibles sans la clé.",
    "SQL_INJECTION": "Un attaquant peut manipuler les requêtes SQL pour extraire toute la base de données utilisateur ou bypasser l'authentification.",
    "INSECURE_PREFS": "Les données de l'application sont lisibles par toutes les autres applications du téléphone, exposant les secrets de session.",
    "LOCKOUT_VULNERABLE": "L'absence de blocage permet à un attaquant de tester des millions de mots de passe (Brute Force) jusqu'à trouver le bon.",
    "ENUMERATION_VULNERABLE": "Le serveur confirme l'existence des comptes, facilitant le ciblage précis pour des attaques de phishing ou de force brute."
}

def add_timeline_event(message, severity="INFO"):
    from datetime import datetime
    event = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "message": message,
        "severity": severity
    }
    if "timeline" not in session_state: session_state["timeline"] = []
    session_state["timeline"].append(event)
    save_session(session_state)


def extract_java_context(content, match_start, window=500):
    """Extrait le vrai bloc de code Java autour du match."""
    start = max(0, match_start - window)
    end = min(len(content), match_start + window)
    chunk = content[start:end]
    
    # On trouve les vraies lignes complètes pour faire propre
    first_newline = chunk.find('\n')
    last_newline = chunk.rfind('\n')
    
    if first_newline != -1 and last_newline != -1 and first_newline < last_newline:
        return chunk[first_newline:last_newline].strip()
    return chunk.strip()

def perform_jadx_scan(apk_path, analysis_id):
    findings = []
    out_dir = os.path.join(UPLOAD_DIR, f"{analysis_id}_out")
    
    # 1. Décompilation avec JADX CLI
    add_timeline_event(f"Début de décompilation JADX pour {os.path.basename(apk_path)}...", "INFO")
    try:
        # On utilise subprocess pour lancer la commande jadx.bat
        result = subprocess.run([JADX_PATH, "-d", out_dir, apk_path], capture_output=True, text=True, timeout=120)
        print(f"[*] JADX terminé (Code retour: {result.returncode})")
        add_timeline_event("Décompilation JADX terminée avec succès.", "SUCCESS")
    except subprocess.TimeoutExpired:
        add_timeline_event("JADX a pris trop de temps (Timeout), passage au scan partiel.", "WARNING")
    except Exception as e:
        print(f"Erreur JADX: {e}")
        return [{"type": "JADX_ERROR", "severity": "INFO", "description": "Erreur lors de la décompilation.", "file": "Erreur", "snippet": str(e)}]

    # 2. Scan des fichiers .java et .xml générés
    print("[*] Scan des fichiers décompilés...")
    try:
        patterns = {
            "JWT_TOKEN_LEAK": {
                "regex": r"eyJ[a-zA-Z0-9._-]{10,}",
                "desc": "Jeton JWT trouvé en clair. Risque de détournement de session.",
                "owasp": "MASVS-AUTH-1"
            },
            "HARDCODED_SECRET": {
                "regex": r"(?i)(password|secret|key|api_key|token|auth|pwd)\s*=\s*['\"]([^'\"]{4,})['\"]",
                "desc": "Secret ou clé exposé en clair.",
                "owasp": "MASVS-STORAGE-1"
            },
            "WEAK_CRYPTO": {
                "regex": r"Cipher\.getInstance\s*\(\s*['\"](DES|AES/ECB|RC4)['\"]",
                "desc": "Algorithme obsolète ou mode non sécurisé (ECB).",
                "owasp": "MASVS-CRYPTO-1"
            },
            "SQL_INJECTION": {
                "regex": r"\.rawQuery\s*\(\s*['\"].*?\s*\+\s*\w+",
                "desc": "Requête SQL vulnérable à l'injection.",
                "owasp": "MASVS-STORAGE-2"
            },
            "INSECURE_HTTP": {
                "regex": r"http://(?!(schemas\.android\.com|www\.w3\.org|ns\.adobe\.com|.*\.apache\.org|.*\.google\.com))[a-zA-Z0-9./_-]+",
                "desc": "Connexion non chiffrée (HTTP).",
                "owasp": "MASVS-NETWORK-1"
            }
        }

        lib_blacklist = ["com/google", "android/support", "androidx", "com/facebook", "com/google/android/gms"]

        for root, _, files in os.walk(out_dir):
            if any(lib in root.replace("\\", "/") for lib in lib_blacklist): continue

            for file_name in files:
                if file_name.endswith(('.java', '.xml')):
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for p_type, p_info in patterns.items():
                                matches = re.finditer(p_info["regex"], content)
                                for m in matches:
                                    snippet = extract_java_context(content, m.start())
                                    clean_file_name = file_path.split("sources")[-1].lstrip("\\/") if "sources" in file_path else file_name
                                    findings.append({
                                        "type": p_type,
                                        "severity": "CRITICAL" if p_type in ["WEAK_CRYPTO", "SQL_INJECTION"] else "HIGH",
                                        "description": p_info["desc"],
                                        "owasp": p_info["owasp"],
                                        "impact": VULN_IMPACT.get(p_type, "Risque de compromission."),
                                        "file": clean_file_name,
                                        "snippet": snippet
                                    })
                                    add_timeline_event(f"Audit : {p_type} détecté dans {clean_file_name}", "HIGH")
                                    break
                    except: continue
    except Exception as e:
        print(f"Scan Error: {e}")

    # 3. Extraction robuste du nom du package
    package_name = "unknown.package"
    try:
        # On cherche le manifest à plusieurs endroits possibles
        manifest_locations = [
            os.path.join(out_dir, "resources", "AndroidManifest.xml"),
            os.path.join(out_dir, "AndroidManifest.xml")
        ]
        
        for loc in manifest_locations:
            if os.path.exists(loc):
                with open(loc, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Regex plus large pour attraper 'package="xxx"' ou 'package=''xxx'''
                    pkg_match = re.search(r'package\s*=\s*["\']([^"\']+)["\']', content)
                    if pkg_match:
                        package_name = pkg_match.group(1)
                        break
        
        print(f"[+] Package identifié : {package_name}")
    except Exception as e:
        print(f"Erreur extraction package: {e}")

    # 4. Extraction des endpoints
    from static_analyzer.endpoint_extractor import extract_auth_endpoints
    endpoints = extract_auth_endpoints(out_dir)
    findings.extend([{
        "type": "ENDPOINT_FOUND",
        "severity": "INFO",
        "description": f"Endpoint détecté : {e['url']}",
        "file": e['file'],
        "snippet": e['url']
    } for e in endpoints["auth_endpoints"]])

    return {"findings": findings, "package_name": package_name, "endpoints": endpoints}

@app.post("/api/analyze/static")
async def analyze_static(apk: UploadFile = File(...)):
    print(f"[*] REQUÊTE REÇUE : Analyse de {apk.filename}")
    analysis_id = str(uuid.uuid4())
    apk_path = os.path.join(UPLOAD_DIR, f"{analysis_id}.apk")
    
    try:
        with open(apk_path, "wb") as f:
            shutil.copyfileobj(apk.file, f)
        print(f"[+] APK sauvegardé : {apk_path}")
    except Exception as e:
        print(f"[!] Erreur sauvegarde APK : {e}")
        return {"status": "error", "message": f"Erreur sauvegarde : {e}"}

    session_state["apk_path"] = apk_path
    analysis_results = perform_jadx_scan(apk_path, analysis_id)
    findings = analysis_results["findings"]
    package_name = analysis_results["package_name"]
    
    if not findings:
        findings.append({"type": "INFO", "severity": "INFO", "description": "Scan JADX terminé.", "file": apk.filename, "snippet": "// Pas de code suspect trouvé."})

    session_state["static_findings"] = findings
    session_state["package_name"] = package_name
    session_state["last_apk"] = apk.filename
    session_state["endpoints"] = analysis_results.get("endpoints", {})
    save_session(session_state)

    # 🚀 PRÉPARATION AUTOMATIQUE DU LAB DYNAMIQUE
    print(f"[*] Préparation automatique du lab pour {package_name}...")
    
    # Lancement du serveur cible si c'est InsecureBankv2
    if package_name and "insecurebankv2" in package_name.lower():
        start_target_server()

    try:
        # Démarrage du proxy s'il n'est pas actif (normalement déjà fait au boot)
        if not proxy_manager.is_running:
            proxy_manager.start()
        
        # Vérification/Bootstrap de Frida en arrière-plan
        # Lancement automatique de Frida (Spawn)
        import threading
        if package_name:
            threading.Thread(target=frida_manager.start_analysis, args=(package_name,)).start()
        else:
            threading.Thread(target=frida_manager._ensure_device).start()
    except Exception as e:
        print(f"[!] Erreur préparation automatique Frida : {e}")

    return {
        "status": "completed", 
        "apk_name": apk.filename, 
        "findings": findings,
        "package_name": package_name,
        "endpoints": session_state["endpoints"]
    }

def start_target_server():
    """Démarre le serveur AndroLabServer en arrière-plan."""
    server_script = get_target_server_path()
    if server_script and os.path.exists(server_script):
        import threading
        import subprocess
        def run_server():
            try:
                subprocess.run(["python", server_script], capture_output=False)
            except Exception as e:
                print(f"[!] Erreur serveur cible : {e}")

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        print(f"[*] Démarrage automatique du serveur cible : {server_script}", flush=True)
    else:
        print(f"[!] Serveur cible introuvable - configurez TARGET_SERVER_PATH env var", flush=True)

async def trigger_auto_setup_internal():
    """Logique interne de démarrage automatique."""
    package_name = session_state.get("package_name") or "com.android.insecurebankv2"
    print(f"[*] Exécution du setup automatique pour {package_name}...")
    
    # 1. Serveur cible
    if "insecurebankv2" in package_name.lower():
        start_target_server()
        
    # 2. Proxy (Asynchrone via task)
    if not proxy_manager.is_running:
        import asyncio
        asyncio.create_task(proxy_manager.start_async())
        
    # 3. Lancement de l'app via ADB
    try:
        subprocess.run(["adb", "shell", f"am start -n {package_name}/.LoginActivity"], capture_output=True)
        print(f"[*] App {package_name} lancée via ADB")
    except Exception as e:
        print(f"[!] Erreur lancement ADB : {e}")

    # 4. Frida (Spawn/Attach)
    if not hasattr(frida_manager, 'is_connected') or not frida_manager.is_connected:
        import threading
        threading.Thread(target=frida_manager.start_analysis, args=(package_name,)).start()

@app.post("/api/setup/auto")
async def trigger_auto_setup():
    """Endpoint API pour déclencher le setup."""
    await trigger_auto_setup_internal()
    return {"status": "setup_triggered"}

@app.get("/api/session/status")
async def get_session_status():
    """Récupère l'état actuel pour restaurer le frontend après refresh."""
    return {
        "package_name": session_state["package_name"],
        "last_apk": session_state["last_apk"],
        "static_findings": session_state["static_findings"],
        "proxy_active": proxy_manager.is_running,
        "frida_active": frida_manager.session is not None
    }

@app.post("/api/analyze/correlate")
async def analyze_correlate():
    """Corrèle les résultats statiques et dynamiques."""
    traffic = proxy_manager.get_live_results()
    engine = CorrelationEngine(
        static_results={"findings": session_state.get("static_findings", [])},
        dynamic_results=traffic,
        validation_results={"active_tests": session_state.get("attack_results", [])}
    )
    correlations = engine.correlate_all()
    return {"status": "success", "correlations": correlations}

# ── Module 2 : Proxy & Traffic ──────────────────────────────────────────────

@app.post("/api/proxy/start")
async def start_proxy():
    """Démarre le proxy mitmproxy."""
    if proxy_manager.is_running:
        return {"status": "already_running", "port": proxy_manager.port}
    
    result = proxy_manager.start()
    return result

from dynamic_analyzer.frida_manager import frida_manager

@app.post("/api/frida/start")
async def start_frida(package_name: str = "owasp.mstg.uncrackable1"):
    """Démarre l'instrumentation Frida sur le package donné."""
    try:
        frida_manager.start_analysis(package_name)
        return {"status": "started", "package": package_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/frida/results")
async def get_frida_results():
    """Récupère les événements capturés par Frida."""
    return {"results": frida_manager.get_results()}

@app.post("/api/frida/spawn")
async def frida_spawn():
    pkg = session_state.get("package_name")
    if not pkg:
        return {"status": "error", "message": "Aucun package identifié. Téléchargez un APK d'abord."}
    
    try:
        frida_manager.start_analysis(pkg)
        return {"status": "success", "message": f"Application {pkg} lancée avec succès."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/status")
async def get_system_status():
    """Retourne l'état de santé des composants Proxy et Frida."""
    frida_active = frida_manager._is_running
    proxy_active = proxy_manager.is_running
    device_connected = False
    try:
        if frida_manager.device:
            frida_manager.device.enumerate_processes()
            device_connected = True
    except: pass
    
    return {
        "proxy": proxy_active,
        "frida": frida_active,
        "device": device_connected,
        "package": session_state.get("package_name")
    }

@app.get("/api/proxy/traffic")
async def get_traffic():
    """Récupère les flux interceptés et les analyse en temps réel."""
    if not proxy_manager.is_running:
        return {
            "error": "Proxy not running",
            "flows": [],
            "findings": session_state["static_findings"],
            "risk_score": "0/150",
            "risk_level": "FAIBLE",
            "frida_events": []
        }
    
    raw_results = proxy_manager.get_live_results()
    
    # 🧠 INTÉGRATION DES FLUX FRIDA (Si le proxy est bypassé)
    frida_events = frida_manager.get_results()
    frida_flows = []
    for ev in frida_events:
        if ev.get("type") == "FRIDA_FLOW":
            frida_flows.append({
                "id": f"frida_{len(frida_flows)}",
                "method": ev.get("method", "GET"),
                "url": ev.get("url", ""),
                "is_auth": "login" in ev.get("url", "").lower(),
                "request": {"headers": ev.get("request_headers", {}), "body": "[Captured by Frida]"},
                "response": {"status_code": 200, "body": "[Response content hidden]"}
            })
    
    # Fusion des flux (Proxy + Frida)
    all_flows = raw_results.get("flows", [])
    # Dédoublonnage sommaire par URL/Méthode si nécessaire
    for ff in frida_flows:
        if not any(f["url"] == ff["url"] and f["method"] == ff["method"] for f in all_flows):
            all_flows.append(ff)
            
    raw_results["flows"] = all_flows
    
    # 🧠 ANALYSE INTELLIGENTE (ML)
    enriched_jwts = extract_jwts_from_traffic(raw_results)
    traffic_findings = parse_captured_traffic(raw_results)
    ml_anomalies = ml_analyzer.analyze_traffic(raw_results.get("flows", []))
    traffic_findings.extend(ml_anomalies)

    # 🔗 LIAISON FINDINGS -> FLOWS
    # On attache les findings à chaque flow pour l'affichage UI
    for finding in traffic_findings:
        if finding.get("flow_id"):
            for flow in raw_results["flows"]:
                if flow.get("id") == finding["flow_id"]:
                    if "findings" not in flow: flow["findings"] = []
                    flow["findings"].append(finding)
    
    # Dédoublonnage et Scoring
    all_findings = session_state["static_findings"] + traffic_findings
    unique_findings = {}
    for f in all_findings:
        # Clé de dédoublonnage intelligente
        if f.get("flow_id"):
            key = f"flow_{f['flow_id']}_{f.get('type')}"
        else:
            key = f"static_{f.get('type')}_{f.get('file', '')}"
            
        if key not in unique_findings:
            f_type = f.get("type", "UNKNOWN")
            f["impact"] = VULN_IMPACT.get(f_type, "Un attaquant pourrait compromettre les données ou la session de l'utilisateur.")
            f['owasp'] = risk_scorer.get_masvs_mapping(f_type)
            unique_findings[key] = f

    # Calcul du score réel (Phase 5)
    score_details = risk_scorer.calculate_score(list(unique_findings.values()))
    score_breakdown = risk_scorer.get_score_breakdown(list(unique_findings.values()))
    
    # Statistiques pour graphiques
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in unique_findings.values():
        sev = f.get("severity", "LOW")
        if sev in stats: stats[sev] += 1

    # 🧠 SYNC FRIDA -> TIMELINE
    for event in frida_events:
        # On évite les doublons simples par message
        if not any(t.get('message') == event.get('message') for t in session_state.get("timeline", [])):
            if event.get('type') in ['AUTH_CAPTURE', 'FRIDA_FLOW', 'SYSTEM']:
                add_timeline_event(event.get('message', ''), event.get('severity', 'INFO'))

    return {
        "flows": raw_results.get("flows", []),
        "jwt_tokens": enriched_jwts,
        "findings": list(unique_findings.values()),
        "frida_events": frida_events,
        "risk_score": f"{score_details['score']}/{score_details['max_score']}",
        "risk_level": score_details['level'],
        "score_breakdown": score_breakdown,
        "timeline": session_state.get("timeline", []),
        "ai_remediations": ai_recommender.generate_remediations(list(unique_findings.values())),
        "stats": stats,
        "total_requests": raw_results.get("total_requests", 0),
        "attack_results": session_state.get("attack_results", [])
    }

@app.get("/api/report/pdf")
async def generate_pdf_report():
    """Génère un rapport PDF professionnel (Phase 6)."""
    try:
        report_path = os.path.join(UPLOAD_DIR, "audit_report.pdf")
        
        # On récupère toutes les données actuelles via get_traffic() qui fusionne déjà tout
        traffic_data = await get_traffic()
        findings = traffic_data["findings"]
        
        # Intelligence Artificielle (Claude Integration)
        ai_reco_list = ai_recommender.generate_remediations(findings)
        ai_reco_text = "Priorités de remédiation :\n" + "\n".join([f"- {r['title']}: {r['action']}" for r in ai_reco_list])
    
        # Préparation du score pour le PDF
        try:
            score_num = int(traffic_data["risk_score"].split('/')[0])
        except:
            score_num = 0
            
        data = {
            "apk_name": session_state.get("last_apk", "N/A"),
            "package_name": session_state.get("package_name", "N/A"),
            "risk_score_details": {
                "score": score_num,
                "max_score": 150,
                "level": traffic_data["risk_level"],
                "vulnerabilities_count": len(findings)
            },
            "findings": findings,
            "attack_results": session_state.get("attack_results", []),
            "ai_recommendations": ai_reco_text
        }
        
        gen = PDFReportGenerator(report_path)
        gen.generate(data)
        
        if not os.path.exists(report_path):
            raise HTTPException(status_code=500, detail="Échec de génération du fichier PDF.")
            
        return FileResponse(report_path, media_type="application/pdf", filename="rapport_audit_complet.pdf")
    except Exception as e:
        print(f"[!] Erreur Rapport PDF : {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ── Module 3 : Validation Active ───────────────────────────────────────────
from active_validator.bruteforce_tester import BruteforceTester
from active_validator.jwt_attacker import JWTAttacker
from active_validator.session_tester import SessionLifecycleTester

bruteforce_tester = BruteforceTester()
jwt_attacker = JWTAttacker()
session_tester = SessionLifecycleTester()

def translate_url(url: str) -> str:
    """Traduit 10.0.2.2 (émulateur) en 127.0.0.1 (host) pour le backend."""
    if not url: return url
    return url.replace("10.0.2.2", "127.0.0.1")

@app.post("/api/attack/session/lockout")
@app.post("/api/attack/session/lockout/")
async def attack_lockout(login_url: str = None, username: str = "admin"):
    """Lance un test de lockout policy."""
    try:
        if not login_url:
            # On tente de trouver l'URL de login dans les endpoints détectés
            login_url = session_state.get("endpoints", {}).get("auth_endpoints", [{}])[0].get("url", "http://127.0.0.1:8888/login")
        
        target = translate_url(login_url)
        add_timeline_event(f"Attaque : Test de Lockout sur {target}", "INFO")
        evidence = await bruteforce_tester.test_lockout_policy(target, username)
        return {
            "status": "VULNÉRABLE" if evidence.get("is_vulnerable") else "SÉCURISÉ",
            "message": evidence.get("summary", "Test terminé."),
            "evidence": evidence,
            "owasp": "MASVS-AUTH-5"
        }
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

@app.post("/api/attack/session/enumeration")
@app.post("/api/attack/session/enumeration/")
async def attack_enumeration(login_url: str = None, valid_username: str = "admin"):
    """Lance un test d'énumération d'utilisateurs."""
    try:
        if not login_url:
            login_url = session_state.get("endpoints", {}).get("auth_endpoints", [{}])[0].get("url", "http://127.0.0.1:8888/login")
            
        target = translate_url(login_url)
        add_timeline_event(f"Attaque : Test d'Énumération sur {target}", "INFO")
        evidence = await bruteforce_tester.test_username_enumeration(target, valid_username)
        return {
            "status": "VULNÉRABLE" if evidence.get("vulnerability_confirmed") else "SÉCURISÉ",
            "message": evidence.get("summary", "Test terminé."),
            "evidence": evidence,
            "owasp": "MASVS-AUTH-5"
        }
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

@app.post("/api/attack/session/capture")
@app.post("/api/attack/session/capture/")
async def attack_session_capture():
    """Vérifie si un token a été capturé dans le trafic actuel."""
    from dynamic_analyzer.jwt_interceptor import extract_jwts_from_traffic
    traffic = proxy_manager.get_live_results()
    jwts = extract_jwts_from_traffic(traffic)
    
    if jwts:
        add_timeline_event(f"Attaque : {len(jwts)} token(s) capturé(s) !", "SUCCESS")
        return {
            "status": "VULNÉRABLE",
            "message": f"{len(jwts)} token(s) JWT intercepté(s) en clair.",
            "evidence": jwts[0],
            "owasp": "MASVS-AUTH-3"
        }
    return {
        "status": "NON APPLICABLE",
        "message": "Aucun token JWT détecté. Connectez-vous sur l'application Android.",
        "owasp": "MASVS-AUTH-3"
    }

@app.post("/api/attack/session/jwt_none")
@app.post("/api/attack/session/jwt_none/")
async def attack_jwt_alg_none(token: str = None, target_url: str = None):
    """Teste l'attaque alg:none sur le token capturé."""
    try:
        if not token:
            from dynamic_analyzer.jwt_interceptor import extract_jwts_from_traffic
            jwts = extract_jwts_from_traffic(proxy_manager.get_live_results())
            if not jwts:
                return {"status": "NON APPLICABLE", "message": "Aucun token capturé pour tester alg:none."}
            token = jwts[0]["token"]
        
        if not target_url:
            target_url = "http://127.0.0.1:8888/login"

        target = translate_url(target_url)
        add_timeline_event("Attaque : Test JWT alg:none...", "INFO")
        evidence = await jwt_attacker.attack_alg_none(token, target)
        return {
            "status": "VULNÉRABLE" if evidence.get("vulnerability_confirmed") else "SÉCURISÉ",
            "message": evidence.get("summary", "Bypass de signature testé."),
            "evidence": evidence,
            "owasp": "MASVS-AUTH-1"
        }
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

@app.post("/api/attack/session/jwt_crack")
async def attack_jwt_crack(token: str = None):
    """Tente de cracker le secret d'un token JWT."""
    if not token or token == "undefined" or ".test" in token:
        from dynamic_analyzer.jwt_interceptor import extract_jwts_from_traffic
        jwts = extract_jwts_from_traffic(proxy_manager.get_traffic())
        if jwts:
            token = jwts[0]["token"]
        else:
            return {"cracked": False, "message": "Aucun token trouvé."}

    result = token_analyzer.crack_jwt_secret(token)
    if result.get("cracked"):
        session_state["attack_results"].append({
            "type": "JWT Secret Cracking",
            "target": "JWT Header/Signature",
            "status": "VULNÉRABLE",
            "owasp": "MASVS-AUTH-2",
            "details": result.get("message", ""),
            "evidence": f"Secret: {result.get('secret')} (Entropie: {result.get('entropy')})"
        })
        save_session(session_state)
    return result

@app.post("/api/attack/chain")
@app.post("/api/attack/chain/")
async def attack_chain():
    """Lance la chaîne d'attaque automatique."""
    print("[*] REQUÊTE REÇUE : Lancement de l'Exploit Chain...")
    pkg = session_state.get("package_name")
    if not pkg:
        return {"status": "error", "message": "Aucun package chargé."}
    
    # Base URL du serveur cible (InsecureBank)
    target_url = "http://127.0.0.1:8888"
    
    from dynamic_analyzer.jwt_interceptor import extract_jwts_from_traffic
    jwts = extract_jwts_from_traffic(proxy_manager.get_traffic())
    
    chain = AutoAttackChain(target_url, session_state["static_findings"], jwts)
    result = await chain.run()
    
    if result["status"] == "success":
        session_state["attack_results"].append({
            "type": "FULL EXPLOIT CHAIN",
            "target": target_url,
            "status": "VULNÉRABLE (CRITIQUE)",
            "owasp": "MASVS-AUTH-1 / STORAGE-1",
            "details": result["summary"],
            "evidence": "\n".join(result["evidence"])
        })
        save_session(session_state)
    
    return result

@app.post("/api/attack/session/fixation")
@app.post("/api/attack/session/fixation/")
async def attack_session_fixation(login_url: str = None, username: str = "admin", password: str = "admin@123"):
    """Teste la session fixation."""
    target = translate_url(login_url)
    frida_manager.results.append({"type": "SYSTEM", "message": f"Test Session Fixation sur {target}...", "severity": "INFO", "timestamp": "now"})
    evidence = await session_tester.test_session_fixation(target, username, password)
    is_vuln = evidence.get("is_vulnerable")
    session_state["attack_results"].append({
        "type": "SESSION_FIXATION_EXPLOIT",
        "severity": "CRITICAL" if is_vuln else "INFO",
        "target": target,
        "status": "VULNÉRABLE" if is_vuln else "SÉCURISÉ",
        "owasp": "MASVS-AUTH-1",
        "details": evidence.get("details", "")
    })
    save_session(session_state)
    return evidence

@app.post("/api/attack/session/timeout")
@app.post("/api/attack/session/timeout/")
async def attack_session_timeout(target_url: str = None):
    """Teste le timeout de session."""
    target = translate_url(target_url)
    frida_manager.results.append({"type": "SYSTEM", "message": f"Test Session Timeout sur {target}...", "severity": "INFO", "timestamp": "now"})
    evidence = await session_tester.test_session_timeout(target, "fake_token")
    return evidence

@app.post("/api/attack/session/concurrent")
@app.post("/api/attack/session/concurrent/")
async def attack_session_concurrent(login_url: str = None, username: str = "admin", password: str = "admin@123"):
    """Teste les sessions concurrentes."""
    target = translate_url(login_url)
    frida_manager.results.append({"type": "SYSTEM", "message": f"Test Sessions Concurrentes sur {target}...", "severity": "INFO", "timestamp": "now"})
    evidence = await session_tester.test_concurrent_sessions(target, username, password)
    is_vuln = evidence.get("is_vulnerable")
    session_state["attack_results"].append({
        "type": "CONCURRENT_SESSIONS_EXPLOIT",
        "severity": "HIGH" if is_vuln else "INFO",
        "target": target,
        "status": "VULNÉRABLE" if is_vuln else "SÉCURISÉ",
        "owasp": "MASVS-AUTH-3",
        "details": evidence.get("summary", ""),
        "evidence": evidence.get("details", "")
    })
    save_session(session_state)
    return evidence

@app.post("/api/attack/token-replay")
@app.post("/api/attack/token-replay/")
async def attack_token_replay(login_url: str = None):
    """Teste le rejeu de token après logout."""
    try:
        import httpx
        target = translate_url(login_url)
        base_url = target.rsplit('/', 1)[0] # Extract base (e.g. http://127.0.0.1:8888)
        
        frida_manager.results.append({"type": "SYSTEM", "message": "Test Token Replay After Logout...", "severity": "INFO", "timestamp": "now"})
        
        async with httpx.AsyncClient() as client:
            # 1. Login
            login_resp = await client.post(f"{base_url}/login", data={"username": "admin", "password": "admin@123"})
            cookies = login_resp.cookies
            
            # 2. Logout
            await client.post(f"{base_url}/logout")
            
            # 3. Replay
            replay_resp = await client.get(f"{base_url}/dashboard", cookies=cookies)
            
            vulnerable = replay_resp.status_code == 200
            result = {
                "vulnerability_confirmed": vulnerable,
                "summary": "Token Replay After Logout",
                "severity": "CRITICAL",
                "owasp": "MASVS-AUTH-3",
                "evidence": f"HTTP {replay_resp.status_code} — session encore active après logout" if vulnerable else "Session invalidée correctement.",
                "score": 30 if vulnerable else 0
            }
            
            session_state["attack_results"].append({
                "type": "Token Replay After Logout",
                "target": f"{base_url}/dashboard",
                "status": "VULNÉRABLE" if vulnerable else "SÉCURISÉ",
                "owasp": result["owasp"],
                "details": result["summary"],
                "evidence": result["evidence"]
            })
            save_session(session_state)
            return result
    except Exception as e:
        print(f"[!] Erreur Token Replay : {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/attack/session/lifecycle-full")
async def attack_lifecycle_full():
    """Exécute le cycle de vie complet de la session."""
    from active_validator.lifecycle_tester import LifecycleTester
    from dynamic_analyzer.jwt_interceptor import extract_jwts_from_traffic
    
    traffic = proxy_manager.get_live_results()
    jwts = extract_jwts_from_traffic(traffic)
    token = jwts[0]["token"] if jwts else None
    
    # URL de base pour InsecureBank ou autre
    login_url = session_state.get("endpoints", {}).get("auth_endpoints", [{}])[0].get("url", "http://127.0.0.1:8888/login")
    base_url = login_url.rsplit('/', 1)[0]
    
    tester = LifecycleTester(base_url, token)
    results = tester.run_full_lifecycle({
        "logout_url": "/logout",
        "protected_url": "/dashboard"
    })
    
    total_score = sum(r.get("score", 0) for r in results)
    critical_found = any(r.get("status") == "VULNÉRABLE" for r in results)
    
    return {
        "status": "success",
        "steps": results,
        "total_score": total_score,
        "critical_found": critical_found
    }

@app.get("/api/logs/server")
async def get_server_logs():
    """Lit les logs du serveur cible (local ou via proxy)."""
    # 1. Tenter le log local (InsecureBank)
    server_script = get_target_server_path()
    if server_script:
        log_path = server_script.replace("server_v3.py", "server_access.log")
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                # Strip whitespace and filter empty lines, return last 50
                clean_lines = [l.rstrip('\n\r') for l in lines if l.strip()]
                return {"logs": clean_lines[-50:]}
            except: pass
    
    # 2. Sinon, retourner le trafic du proxy (flows récents)
    if proxy_manager.is_running:
        flows = proxy_manager.get_traffic().get("flows", [])
        logs = []
        for f in flows[-15:]:
            status = f.get('response', {}).get('status_code', '...')
            logs.append(f"[{status}] {f['method']} {f['url']}")
        if logs:
            return {"logs": logs}
    
    return {"logs": ["[En attente de trafic ou de logs serveur...]"]}

@app.post("/api/llm/analyze")
async def llm_analyze(data: dict):
    """Analyse les vulnérabilités avec l'IA réelle (Ollama ou Gemini)."""
    findings = data.get('findings', [])
    package = data.get('package', session_state.get("package_name", "Unknown"))
    
    if not findings:
        return {"executive_summary": "Aucune vulnérabilité détectée pour analyse.", "vulnerabilities": []}

    # Appel au moteur d'IA (Ollama/Gemini)
    try:
        remediations = ai_recommender.generate_remediations(findings)
        
        # Adaptation au format attendu par le frontend
        return {
            "executive_summary": f"L'analyse IA de {package} a identifié {len(remediations)} points d'attention prioritaires basés sur l'audit MSTG.",
            "critical_risk": remediations[0]['risk'] if remediations else "Risque global modéré.",
            "vulnerabilities": [
                {
                    "type": r['title'],
                    "impact": r['risk'],
                    "fix_code": r['code_fix'],
                    "priority": r['priority'],
                    "action": r['action']
                } for r in remediations
            ],
            "overall_grade": "CRITICAL" if any(r['priority'] == 'CRITIQUE' for r in remediations) else "B"
        }
    except Exception as e:
        print(f"[!] Erreur IA : {e}")
        return {"executive_summary": "Erreur lors de la consultation de l'IA locale.", "vulnerabilities": []}

@app.post("/api/correlation/analyze")
async def correlation_analyze():
    """Analyse les corrélations entre statique et dynamique."""
    correlations = []
    # Simulation d'analyse croisée
    for f in session_state.get("static_findings", []):
        if "secret" in f["type"].lower() or "password" in f["type"].lower():
            correlations.append({
                "type": "SECRET_LEAK_CONFIRMED",
                "static_file": f["file"],
                "dynamic_url": "http://127.0.0.1:8888/login",
                "confidence": 0.95
            })
    return {"correlations": correlations}

# =============================================================================
# NOUVEAUX ENDPOINTS - TOKEN LIFETIME & ROTATION & MASVS
# =============================================================================

@app.post("/api/analyze/token/lifetime")
async def analyze_token_lifetime(tokens: list = None):
    """
    Analyse la durée de vie et la sécurité des tokens JWT.

    Vérifie :
    - Claims temporels (exp, iat, nbf)
    - Durée de vie excessive
    - Algorithmes de signature
    - Claims requis
    """
    try:
        if not tokens:
            # Extraire les tokens du trafic actuel
            from dynamic_analyzer.jwt_interceptor import extract_jwts_from_traffic
            traffic = proxy_manager.get_live_results()
            jwts = extract_jwts_from_traffic(traffic)

            if not jwts:
                return {"status": "no_tokens", "message": "Aucun token JWT capturé pour analyse"}

            tokens = [{"token": j["token"], "type": "access"} for j in jwts]

        # Analyser les tokens
        if isinstance(tokens, list) and len(tokens) > 0:
            if isinstance(tokens[0], dict):
                results = token_lifetime_analyzer.analyze_multiple_tokens(tokens)
            else:
                results = token_lifetime_analyzer.analyze_token(tokens[0])
        else:
            results = {"error": "Format de tokens invalide"}

        return {"status": "success", "analysis": results}

    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/analyze/token/rotation")
async def analyze_token_rotation(login_url: str = None, credentials: dict = None):
    """
    Teste la rotation des tokens (refresh token security).

    Tests exécutés :
    - Refresh token one-time use
    - Access token change on refresh
    - Family tracking
    - Concurrent refresh attack detection
    """
    try:
        if not login_url:
            login_url = session_state.get("endpoints", {}).get("auth_endpoints", [{}])[0].get("url", "http://127.0.0.1:8888/login")

        base_url = login_url.rsplit('/', 1)[0]
        tester = TokenRotationTester(base_url=base_url)

        creds = credentials or {"username": "admin", "password": "admin@123"}
        results = await tester.run_all_rotation_tests(
            refresh_endpoint=f"{base_url}/token/refresh",
            credentials=creds
        )

        # Sauvegarder les résultats
        session_state["attack_results"].append({
            "type": "TOKEN_ROTATION_ANALYSIS",
            "target": base_url,
            "status": results.get("summary", {}).get("overall_status", "UNKNOWN"),
            "owasp": "MASVS-AUTH-5",
            "details": results
        })
        save_session(session_state)

        return {"status": "success", "rotation_tests": results}

    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/masvs/generate-checklist")
async def generate_masvs_checklist(auth_type: str = None):
    """
    Génère une checklist de conformité MASVS basée sur l'analyse.

    Args:
        auth_type: Type d'authentification (auto-détecté si None)
                   Options: jwt, oauth2, session, all
    """
    try:
        # Utiliser les findings actuels
        static_findings = session_state.get("static_findings", [])

        # Récupérer le trafic dynamique pour analyse complémentaire
        traffic = proxy_manager.get_live_results() if proxy_manager.is_running else {"flows": []}
        dynamic_findings = traffic.get("findings", [])

        # Générer la checklist
        checklist = checklist_generator.generate_checklist(
            static_findings=static_findings,
            dynamic_findings=dynamic_findings,
            auth_type=auth_type,
            app_name=session_state.get("package_name", "Unknown App")
        )

        # Sauvegarder dans la session
        session_state["masvs_checklist"] = checklist
        save_session(session_state)

        return {
            "status": "success",
            "checklist": checklist,
            "markdown": checklist_generator.export_markdown(checklist)
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/masvs/detect-auth-type")
async def detect_authentication_type():
    """
    Détecte automatiquement le type d'authentification utilisé par l'application.

    Returns:
        Type d'auth détecté avec preuves et confiance
    """
    try:
        static_findings = session_state.get("static_findings", [])

        # Analyse statique
        static_result = auth_type_detector.analyze_static_findings(static_findings)

        # Analyse dynamique (si trafic disponible)
        dynamic_result = {"detected_types": [], "evidence": []}
        if proxy_manager.is_running:
            traffic = proxy_manager.get_live_results()
            dynamic_result = auth_type_detector.analyze_dynamic_traffic(traffic.get("flows", []))

        # Analyse des endpoints
        endpoint_result = {"detected_types": [], "evidence": []}
        if session_state.get("endpoints"):
            endpoint_result = auth_type_detector.analyze_endpoints(session_state["endpoints"])

        # Combiner les résultats
        all_types = set()
        all_types.update(static_result.get("all_detected_types", []))
        all_types.update(dynamic_result.get("detected_types", []))
        all_types.update(endpoint_result.get("detected_types", []))

        return {
            "status": "success",
            "primary_auth_type": static_result.get("primary_auth_type", "unknown"),
            "all_detected_types": list(all_types),
            "confidence": static_result.get("confidence", {}),
            "static_evidence": static_result.get("evidence", []),
            "dynamic_evidence": dynamic_result.get("evidence", []),
            "endpoint_evidence": endpoint_result.get("evidence", [])
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/masvs/acceptance-criteria")
async def generate_acceptance_criteria(user_story: str = None):
    """
    Génère des critères d'acceptation de sécurité pour une user story.

    Args:
        user_story: Description de la user story (optionnel)
    """
    try:
        # Utiliser la checklist existante ou en générer une nouvelle
        checklist = session_state.get("masvs_checklist")
        if not checklist:
            # Générer une nouvelle checklist
            static_findings = session_state.get("static_findings", [])
            checklist = checklist_generator.generate_checklist(
                static_findings=static_findings,
                app_name=session_state.get("package_name", "Unknown App")
            )

        # Générer les critères d'acceptation
        criteria = checklist_generator.generate_security_acceptance_criteria(
            checklist=checklist,
            user_story=user_story or "Authentication feature"
        )

        return {
            "status": "success",
            "user_story": user_story or "Authentication feature",
            "acceptance_criteria": criteria,
            "total_criteria": len(criteria)
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/api/masvs/checklist/export")
async def export_checklist(format: str = "markdown"):
    """
    Exporte la checklist MASVS dans un format spécifique.

    Args:
        format: "markdown", "json", "html"
    """
    try:
        checklist = session_state.get("masvs_checklist")
        if not checklist:
            return {"status": "error", "message": "Aucune checklist générée. Appelez d'abord /api/masvs/generate-checklist"}

        if format == "json":
            return {
                "status": "success",
                "content": checklist_generator.export_json(checklist),
                "content_type": "application/json"
            }
        elif format == "markdown":
            return {
                "status": "success",
                "content": checklist_generator.export_markdown(checklist),
                "content_type": "text/markdown"
            }
        else:
            return {"status": "error", "message": f"Format non supporté: {format}"}

    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/analyze/storage")
async def analyze_storage_security():
    """
    Analyse la sécurité du stockage des tokens et données sensibles.

    Détecte:
    - Stockage insecure dans SharedPreferences
    - Fuites dans Logcat
    - Tokens dans URLs
    - Envoi à des SDKs analytics
    - Stockage fichier non sécurisé
    """
    try:
        # Vérifier si le code source est disponible
        jadx_dir = session_state.get("jadx_output_dir")
        if not jadx_dir or not os.path.exists(jadx_dir):
            return {"status": "error", "message": "Code source non disponible. Analysez d'abord l'APK."}

        # Scanner le stockage
        storage_results = storage_scanner.analyze_token_storage(
            tokens=[],  # Tokens déjà dans session_state
            source_dir=jadx_dir
        )

        # Vérifier l'usage de stockage sécurisé
        secure_storage = storage_scanner.check_secure_storage_usage(jadx_dir)

        # Sauvegarder les résultats
        session_state["storage_analysis"] = {
            **storage_results,
            "secure_storage_usage": secure_storage
        }
        save_session(session_state)

        return {
            "status": "success",
            "storage_analysis": storage_results,
            "secure_storage": secure_storage
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/session/reset")
async def reset_session():
    """Réinitialise l'état de la session."""
    global session_state
    session_state = {
        "package_name": "com.android.insecurebankv2",
        "last_apk": None,
        "static_findings": [],
        "masvs_checklist": None,
        "storage_analysis": None
    }
    proxy_manager.addon.flows = []
    proxy_manager.addon.jwt_tokens = []
    frida_manager.results = []
    return {"status": "reset"}

app.mount("/", StaticFiles(directory=os.path.join(ROOT_DIR, "frontend"), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    # Le setup automatique est maintenant géré par startup_event ou déclenché via /api/setup/auto
    uvicorn.run(app, host="127.0.0.1", port=8001)
