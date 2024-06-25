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
            f.write("[Desktop Entry]\nType=Application\nName=Satochip Utils\nExec=satochip_utils\nCategories=Utility;")

        # List contents of AppDir
        logger.info("Contents of AppDir:")
        for root, dirs, files in os.walk("AppDir"):
            for file in files:
                logger.info(os.path.join(root, file))

        # AppImage command
        appimage_command = [
            "./appimagetool-x86_64.AppImage",
            "AppDir",
            "satochip_utils.AppImage"
        ]

        # Run AppImage command without check=True to capture output even if it fails
        result = subprocess.run(appimage_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.info(f"AppImage command exit code: {result.returncode}")
        logger.info(f"AppImage STDOUT:\n{result.stdout}")
        logger.info(f"AppImage STDERR:\n{result.stderr}")

        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, appimage_command, result.stdout, result.stderr)

        logger.info("AppImage created successfully.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
        logger.error(f"STDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}")
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        raise


if __name__ == "__main__":
    run_pyinstaller()