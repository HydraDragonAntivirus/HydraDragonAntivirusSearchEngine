import os
import sys
from cx_Freeze import setup, Executable

# This script is for Windows only.
if sys.platform != "win32":
    sys.exit("This setup script is intended for Windows only.")

# For a Windows GUI application, use the Win32GUI base.
base = "Win32GUI"

# Build options – include packages used in your application.
build_options = {
    "packages": ["PySide6", "requests"],
    "excludes": ["tkinter"],
    # Include additional files (e.g., icons, models) as needed.
    "include_files": [
        ("assets/HydraDragonAV.ico", "assets/HydraDragonAV.ico"),
    ]
}

# Define the executable.
executables = [
    Executable(
        "hydradragonantivirussearchengine.py",  # Main script filename.
        target_name="HydraDragonAntivirusSearchEngine.exe",
        base=base,
        icon="assets/HydraDragonAV.ico",
        uac_admin=True  # Request admin privileges.
    )
]

# Setup configuration.
setup(
    name="HydraDragonAntivirusSearchEngine",
    version="0.1",
    description="Hydra Dragon Antivirus Search Engine",
    options={"build": build_options},
    executables=executables,
)
