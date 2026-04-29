"""
static_analyzer/apk_decompiler.py
─────────────────────────────────
Décompilation automatique d'un APK via jadx.
"""

import subprocess
import os
import sys
from pathlib import Path

# Import config depuis le dossier parent
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import JADX_PATH, JADX_LINUX, SCAN_TIMEOUT


def get_jadx_path() -> str:
    """Retourne le chemin vers jadx selon l'OS."""
    if sys.platform == "win32":
        return JADX_PATH
    return JADX_LINUX


def decompile_apk(apk_path: str, output_dir: str) -> str:
    """
    Décompile un APK avec jadx.

    Args:
        apk_path:   Chemin absolu vers le fichier .apk
        output_dir: Dossier de sortie pour les fichiers décompilés

    Returns:
        output_dir si succès

    Raises:
        FileNotFoundError: si l'APK n'existe pas
        RuntimeError:      si jadx échoue
    """
    # Vérifier que l'APK existe
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    # Vérifier que jadx est installé
    jadx_path = get_jadx_path()
    if not os.path.exists(jadx_path):
        raise RuntimeError(f"JADX not found at: {jadx_path}")

    # Créer le dossier de sortie s'il n'existe pas
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Lancer jadx -d output_dir apk_path
        if sys.platform == "win32":
            cmd = [jadx_path, "-d", output_dir, apk_path]
        else:
            cmd = ["java", "-jar", jadx_path, "-d", output_dir, apk_path]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT
        )

        if result.returncode != 0:
            raise RuntimeError(f"JADX failed: {result.stderr}")

        # Vérifier que la décompilation a réussi (dossier non vide)
        if not os.path.exists(output_dir) or not os.listdir(output_dir):
            raise RuntimeError("Decompilation failed - output directory is empty")

        return output_dir

    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Decompilation timeout after {SCAN_TIMEOUT} seconds")
    except Exception as e:
        raise RuntimeError(f"Decompilation error: {str(e)}")


def extract_manifest(decompiled_dir: str) -> str:
    """
    Trouve et retourne le chemin vers AndroidManifest.xml.

    Args:
        decompiled_dir: Dossier de sortie jadx

    Returns:
        Chemin absolu vers AndroidManifest.xml
    """
    # Parcourir decompiled_dir pour trouver AndroidManifest.xml
    for root, dirs, files in os.walk(decompiled_dir):
        if "AndroidManifest.xml" in files:
            return os.path.join(root, "AndroidManifest.xml")

    raise FileNotFoundError(f"AndroidManifest.xml not found in {decompiled_dir}")


def get_apk_info(apk_path: str) -> dict:
    """
    Extrait les métadonnées de base d'un APK (package name, version, etc.)

    Returns:
        {"package": str, "version": str, "min_sdk": int, "target_sdk": int}
    """
    # Utiliser aapt pour lire les métadonnées
    try:
        # Essayer d'abord aapt
        result = subprocess.run(
            ["aapt", "dump", "badging", apk_path],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            return parse_aapt_output(result.stdout)
        else:
            # Fallback: utiliser aapt2 si disponible
            result = subprocess.run(
                ["aapt2", "dump", "badging", apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return parse_aapt_output(result.stdout)

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        # Si aapt n'est pas disponible, retourner des informations de base
        return {
            "package": "unknown",
            "version": "unknown",
            "min_sdk": 0,
            "target_sdk": 0,
            "error": f"aapt not available: {str(e)}"
        }

    # Si tout échoue, retourner des valeurs par défaut
    return {
        "package": "unknown",
        "version": "unknown",
        "min_sdk": 0,
        "target_sdk": 0
    }


def parse_aapt_output(aapt_output: str) -> dict:
    """
    Parse la sortie de aapt dump badging.

    Args:
        aapt_output: Sortie texte de aapt

    Returns:
        Dictionnaire avec les métadonnées de l'APK
    """
    info = {
        "package": "unknown",
        "version": "unknown",
        "min_sdk": 0,
        "target_sdk": 0
    }

    for line in aapt_output.split('\n'):
        # Extraire le package name
        if line.startswith("package:"):
            parts = line.split()
            for part in parts:
                if part.startswith("name="):
                    info["package"] = part.split('=')[1].strip("'\"")
                elif part.startswith("versionName="):
                    info["version"] = part.split('=')[1].strip("'\"")

        # Extraire les SDK versions
        if "sdkVersion" in line:
            parts = line.split("'")
            if len(parts) >= 2:
                try:
                    info["min_sdk"] = int(parts[1])
                except ValueError:
                    pass

        if "targetSdkVersion" in line:
            parts = line.split("'")
            if len(parts) >= 2:
                try:
                    info["target_sdk"] = int(parts[1])
                except ValueError:
                    pass

    return info
