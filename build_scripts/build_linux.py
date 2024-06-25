import subprocess
import logging
import os

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def run_pyinstaller():
    try:
        command = [
            "pyinstaller",
            "--onefile",
            "--name", "satochip_utils",
            "--add-data", "pysatochip/pysatochip/cert/*:pysatochip/pysatochip/cert",
            "--add-data", "pictures_db/*:pictures_db",
            "--add-data", "pysatochip/pysatochip/CardConnector.py:pysatochip",
            "satochip_utils.py"
        ]

        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.info("Build Linux terminé avec succès.")
        logger.debug(f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")

        # Création de l'AppImage
        os.makedirs("AppDir/usr/bin", exist_ok=True)
        os.system("cp dist/satochip_utils AppDir/usr/bin/")

        appimage_command = [
            "./appimagetool-x86_64.AppImage",
            "AppDir",
            "satochip_utils.AppImage"
        ]

        result = subprocess.run(appimage_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.info("Création de l'AppImage terminée avec succès.")
        logger.debug(f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    except Exception as e:
        logger.error(f"Erreur lors du build Linux : {e}")
        raise


if __name__ == "__main__":
    run_pyinstaller()