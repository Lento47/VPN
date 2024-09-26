import os
import platform
import subprocess
import shutil

def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    if process.returncode != 0:
        print(f"Error executing command: {command}")
        print(error.decode('utf-8'))
        exit(1)
    return output.decode('utf-8')

def create_virtual_env():
    run_command("python -m venv vpn_env")
    if platform.system() == "Windows":
        activate_cmd = ".\\vpn_env\\Scripts\\activate"
    else:
        activate_cmd = "source vpn_env/bin/activate"
    print(f"Virtual environment created. Activate it with: {activate_cmd}")

def install_dependencies():
    run_command("pip install numpy scikit-learn cryptography pyinstaller")
    run_command("pip freeze > requirements.txt")

def create_vpn_app_file():
    with open("vpn_app.py", "w") as f:
        f.write('''
import sys
from vpn_server import VPNServer
from vpn_client_gui import VPNClientGUI
import tkinter as tk

def run_server():
    server = VPNServer("0.0.0.0", 5000)
    server.start()

def run_client():
    root = tk.Tk()
    client_gui = VPNClientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ["server", "client"]:
        print("Usage: python vpn_app.py [server|client]")
        sys.exit(1)

    if sys.argv[1] == "server":
        run_server()
    else:
        run_client()
''')

def create_pyinstaller_spec():
    run_command("pyi-makespec --onefile --add-data \"server.crt:server.crt\" --add-data \"server.key:server.key\" vpn_app.py")

def build_executable():
    run_command("pyinstaller vpn_app.spec")

def create_runner_script():
    if platform.system() == "Windows":
        with open("run_vpn.bat", "w") as f:
            f.write('''@echo off
if "%1"=="server" (
    start "" vpn_app.exe server
) else if "%1"=="client" (
    start "" vpn_app.exe client
) else (
    echo Usage: run_vpn.bat [server^|client]
)
''')
    else:
        with open("run_vpn.sh", "w") as f:
            f.write('''#!/bin/bash
if [ "$1" = "server" ]; then
    ./vpn_app server
elif [ "$1" = "client" ]; then
    ./vpn_app client
else
    echo "Usage: ./run_vpn.sh [server|client]"
fi
''')
        run_command("chmod +x run_vpn.sh")

def create_binaries_folder():
    if not os.path.exists("binaries"):
        os.mkdir("binaries")
    shutil.copy("dist/vpn_app" if platform.system() != "Windows" else "dist/vpn_app.exe", "binaries/")
    shutil.copy("server.crt", "binaries/")
    shutil.copy("server.key", "binaries/")
    shutil.copy("run_vpn.bat" if platform.system() == "Windows" else "run_vpn.sh", "binaries/")

def main():
    print(f"Detected OS: {platform.system()}")
    create_virtual_env()
    install_dependencies()
    create_vpn_app_file()
    create_pyinstaller_spec()
    build_executable()
    create_runner_script()
    create_binaries_folder()
    print("Packaging complete. Check the 'binaries' folder for the packaged application.")

if __name__ == "__main__":
    main()