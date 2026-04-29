"""
static_analyzer/permission_checker.py
───────────────────────────────────────
Analyse des permissions Android dans AndroidManifest.xml.
Détecte les permissions dangereuses selon la classification OWASP/Android.
"""

import xml.etree.ElementTree as ET
import os
from typing import List, Dict, Any


# ─── Classification des permissions ──────────────────────────────────────────
#
# Format : "permission.name": (severity, cvss, description, owasp_ref)
#
DANGEROUS_PERMISSIONS: Dict[str, tuple] = {
    "android.permission.READ_CONTACTS":         ("HIGH",     6.5, "Accès aux contacts",            "M2"),
    "android.permission.WRITE_CONTACTS":        ("HIGH",     6.5, "Modification des contacts",     "M2"),
    "android.permission.ACCESS_FINE_LOCATION":  ("HIGH",     6.8, "GPS précis",                    "M2"),
    "android.permission.ACCESS_COARSE_LOCATION":("MEDIUM",   5.0, "Localisation réseau",           "M2"),
    "android.permission.CAMERA":                ("MEDIUM",   5.0, "Accès caméra",                  "M2"),
    "android.permission.RECORD_AUDIO":          ("HIGH",     6.8, "Enregistrement audio",          "M2"),
    "android.permission.READ_EXTERNAL_STORAGE": ("MEDIUM",   5.5, "Lecture stockage externe",      "M2"),
    "android.permission.WRITE_EXTERNAL_STORAGE":("MEDIUM",   5.5, "Écriture stockage externe",     "M2"),
    "android.permission.SEND_SMS":              ("HIGH",     7.0, "Envoi de SMS",                  "M2"),
    "android.permission.READ_SMS":              ("HIGH",     7.0, "Lecture des SMS",               "M2"),
    "android.permission.CALL_PHONE":            ("HIGH",     7.0, "Appels téléphoniques",          "M2"),
    "android.permission.READ_CALL_LOG":         ("HIGH",     6.5, "Historique d'appels",           "M2"),
    "android.permission.PROCESS_OUTGOING_CALLS":("HIGH",     7.5, "Interception d'appels sortants","M2"),
    "android.permission.READ_PHONE_STATE":      ("MEDIUM",   5.0, "Identifiant téléphonique",      "M2"),
    "android.permission.INTERNET":              ("LOW",      3.1, "Accès Internet",                "M3"),
    "android.permission.USE_BIOMETRIC":         ("MEDIUM",   4.5, "Authentification biométrique",  "M4"),
    "android.permission.USE_FINGERPRINT":       ("MEDIUM",   4.5, "Authentification empreinte",    "M4"),
    "android.permission.RECEIVE_BOOT_COMPLETED":("LOW",      2.5, "Démarrage automatique",         "M6"),
    "android.permission.SYSTEM_ALERT_WINDOW":   ("HIGH",     7.5, "Overlay système (clickjacking)","M7"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":("CRITICAL",9.0,"Service d'accessibilité",    "M7"),
    "android.permission.REQUEST_INSTALL_PACKAGES":("HIGH",   7.8, "Installation d'APK",            "M8"),
    "android.permission.PACKAGE_USAGE_STATS":   ("MEDIUM",   5.5, "Statistiques d'utilisation",   "M2"),
}

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def check_permissions(manifest_path: str) -> List[Dict[str, Any]]:
    """
    Parse AndroidManifest.xml et détecte les permissions dangereuses.

    Args:
        manifest_path: Chemin vers AndroidManifest.xml

    Returns:
        Liste de findings : [{"permission", "severity", "cvss", "description", "owasp_ref"}, ...]
    """
    findings = []

    if not os.path.exists(manifest_path):
        return findings

    try:
        # Parser le XML avec ET.parse
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Itérer sur les <uses-permission> tags
        for permission_elem in root.findall("uses-permission"):
            permission_name = permission_elem.get(f"{{{ANDROID_NS}}}name")

            if permission_name and permission_name in DANGEROUS_PERMISSIONS:
                severity, cvss, description, owasp_ref = DANGEROUS_PERMISSIONS[permission_name]

                findings.append({
                    "type": "DANGEROUS_PERMISSION",
                    "permission": permission_name,
                    "severity": severity,
                    "cvss": cvss,
                    "description": description,
                    "owasp_ref": owasp_ref,
                    "file": manifest_path
                })

        # Retourner les findings triés par cvss
        findings.sort(key=lambda x: x["cvss"], reverse=True)
        return findings

    except ET.ParseError as e:
        print(f"Error parsing AndroidManifest.xml: {e}")
        return findings
    except Exception as e:
        print(f"Error checking permissions: {e}")
        return findings


def check_exported_components(manifest_path: str) -> List[Dict[str, Any]]:
    """
    Détecte les composants Android exportés sans protection (exported=true sans permission).
    Vulnérabilité OWASP M1 — Mauvaise utilisation de la plateforme.

    Returns:
        Liste de composants exposés : [{"component_type", "name", "severity", "description"}, ...]
    """
    findings = []

    if not os.path.exists(manifest_path):
        return findings

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Chercher les <activity>, <service>, <receiver>, <provider> avec android:exported="true"
        component_types = [
            ("activity", "Activity"),
            ("service", "Service"),
            ("receiver", "Broadcast Receiver"),
            ("provider", "Content Provider")
        ]

        for tag_name, component_type in component_types:
            for component in root.findall(tag_name):
                exported = component.get(f"{{{ANDROID_NS}}}exported", "false")
                permission = component.get(f"{{{ANDROID_NS}}}permission")
                component_name = component.get(f"{{{ANDROID_NS}}}name", "unknown")

                if exported.lower() == "true" and not permission:
                    findings.append({
                        "type": "EXPORTED_COMPONENT_NO_PROTECTION",
                        "component_type": component_type,
                        "name": component_name,
                        "severity": "HIGH",
                        "cvss": 7.5,
                        "description": f"{component_type} '{component_name}' is exported without permission protection",
                        "owasp_ref": "M1",
                        "file": manifest_path
                    })

        return findings

    except ET.ParseError as e:
        print(f"Error parsing AndroidManifest.xml: {e}")
        return findings
    except Exception as e:
        print(f"Error checking exported components: {e}")
        return findings


def check_debug_mode(manifest_path: str) -> List[Dict[str, Any]]:
    """
    Détecte si l'application est compilée en mode debug (android:debuggable="true").

    Returns:
        Finding si debuggable = true
    """
    findings = []

    if not os.path.exists(manifest_path):
        return findings

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Chercher android:debuggable="true" dans <application>
        application = root.find("application")
        if application is not None:
            debuggable = application.get(f"{{{ANDROID_NS}}}debuggable", "false")

            if debuggable.lower() == "true":
                findings.append({
                    "type": "DEBUG_MODE_ENABLED",
                    "severity": "HIGH",
                    "cvss": 7.0,
                    "description": "Application is compiled in debug mode, making it easier to reverse engineer and debug",
                    "owasp_ref": "M9",
                    "file": manifest_path
                })

        return findings

    except ET.ParseError as e:
        print(f"Error parsing AndroidManifest.xml: {e}")
        return findings
    except Exception as e:
        print(f"Error checking debug mode: {e}")
        return findings


def check_backup_allowed(manifest_path: str) -> List[Dict[str, Any]]:
    """
    Détecte si la sauvegarde ADB est autorisée (android:allowBackup="true").
    Permet d'extraire les données de l'app via adb backup.

    Returns:
        Finding si allowBackup = true
    """
    findings = []

    if not os.path.exists(manifest_path):
        return findings

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Chercher android:allowBackup dans <application>
        application = root.find("application")
        if application is not None:
            allow_backup = application.get(f"{{{ANDROID_NS}}}allowBackup", "true")

            if allow_backup.lower() == "true":
                findings.append({
                    "type": "BACKUP_ALLOWED",
                    "severity": "MEDIUM",
                    "cvss": 5.5,
                    "description": "Application allows ADB backup, which could expose sensitive data",
                    "owasp_ref": "M2",
                    "file": manifest_path
                })

        return findings

    except ET.ParseError as e:
        print(f"Error parsing AndroidManifest.xml: {e}")
        return findings
    except Exception as e:
        print(f"Error checking backup allowed: {e}")
        return findings
