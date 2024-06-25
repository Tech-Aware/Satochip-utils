import subprocess
import os
import logging
import shutil

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def run_pyinstaller():
    try:
        # PyInstaller command
        pyinstaller_command = [
            "pyinstaller",
            "--onefile",
            "--name", "satochip_utils",
            "--add-data", "pysatochip/pysatochip/cert/*:pysatochip/pysatochip/cert",
            "--add-data", "pictures_db/*:pictures_db",
            "--add-data", "pysatochip/pysatochip/CardConnector.py:pysatochip",
            "satochip_utils.py"
        ]

        result = subprocess.run(pyinstaller_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        logger.info("PyInstaller build completed successfully.")
        logger.debug(f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")

        # Prepare AppDir
        os.makedirs("AppDir/usr/bin", exist_ok=True)
        shutil.copy("dist/satochip_utils", "AppDir/usr/bin/")

        # Create .desktop file
        with open("AppDir/satochip_utils.desktop", "w") as f:
            f.write(
                "[Desktop Entry]\nType=Application\nName=Satochip Utils\nExec=satochip_utils\nIcon=satochip_utils\nCategories=Utility;")

        # Copy icon (assuming you have one, adjust the path as necessary)
        shutil.copy("path/to/your/icon.png", "AppDir/satochip_utils.png")

        # AppImage command
        appimage_command = [
            "./appimagetool-x86_64.AppImage",
            "AppDir",
            "satochip_utils.AppImage"
        ]

        result = subprocess.run(appimage_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.info("AppImage created successfully.")
        logger.debug(f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
        logger.error(f"STDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}")
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        raise


if __name__ == "__main__":
    run_pyinstaller()