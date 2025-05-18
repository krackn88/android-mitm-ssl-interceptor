#!/bin/bash

#############################################################
# Android MITM SSL Interceptor Setup Script
# 
# This script automates the setup of an Android emulator
# configured for SSL/TLS traffic interception.
#
# Features:
# - Installs all required dependencies
# - Sets up Android SDK and emulator
# - Configures mitmproxy with proper certificates
# - Installs Frida for SSL pinning bypass
# - Prepares the environment for APK analysis
#############################################################

set -euo pipefail
IFS=$'\n\t'

# ==== CONFIGURABLE VARIABLES ====
AVD_NAME="mitm-avd"
API_LEVEL="30"
SYS_IMG="system-images;android-${API_LEVEL};google_apis;x86_64"
FRIDA_VER="16.1.11"
MITMPROXY_PORT=8080

# ==== HELPER FUNCTIONS ====
print_banner() {
    echo "========================================================"
    echo "   Android MITM SSL Interceptor - Setup Script"
    echo "========================================================"
    echo ""
}

check_environment() {
    echo "[*] Checking environment..."
    if [[ $EUID -eq 0 ]]; then
        echo "[!] This script should not be run as root!"
        exit 1
    fi
}

# ==== 1. DEPENDENCIES ====
install_dependencies() {
    echo "[*] Installing dependencies..."
    sudo apt-get update
    sudo apt-get install -y openjdk-11-jdk unzip wget python3 python3-pip adb curl
    
    # Python pip packages
    python3 -m pip install --upgrade pip
    pip3 install mitmproxy frida-tools objection
    
    echo "[+] Dependencies installed successfully"
}

# ==== 2. ANDROID SDK + EMULATOR ====
setup_android_sdk() {
    SDK_DIR="$HOME/Android/Sdk"
    CMDLINE_TOOLS_ZIP="commandlinetools-linux-9123335_latest.zip"
    CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/${CMDLINE_TOOLS_ZIP}"
    
    mkdir -p "$SDK_DIR/cmdline-tools"
    cd "$SDK_DIR"
    
    if [ ! -d "$SDK_DIR/cmdline-tools/latest" ]; then
        echo "[*] Downloading Android SDK commandline tools..."
        wget -q "$CMDLINE_TOOLS_URL" -O "$CMDLINE_TOOLS_ZIP"
        unzip -o "$CMDLINE_TOOLS_ZIP" -d "$SDK_DIR/cmdline-tools"
        mv "$SDK_DIR/cmdline-tools/cmdline-tools" "$SDK_DIR/cmdline-tools/latest"
        rm "$CMDLINE_TOOLS_ZIP"
    fi
    
    export ANDROID_SDK_ROOT="$SDK_DIR"
    export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/platform-tools:$PATH"
    
    echo "[*] Accepting SDK licenses..."
    yes | sdkmanager --licenses
    
    echo "[*] Installing SDK components..."
    sdkmanager "platform-tools" "emulator" "$SYS_IMG"
    
    echo "[+] Android SDK setup complete"
}

# ==== 3. CREATE AND LAUNCH AVD ====
create_and_launch_avd() {
    echo "[*] Creating Android Virtual Device ($AVD_NAME)..."
    echo "no" | avdmanager create avd -n "$AVD_NAME" -k "$SYS_IMG" --force --sdcard 2048M
    
    echo "[*] Launching emulator..."
    nohup emulator -avd "$AVD_NAME" -writable-system -no-snapshot -no-window -no-audio -gpu swiftshader_indirect > /tmp/emulator.log 2>&1 &
    EMULATOR_PID=$!
    
    # Wait for device
    echo "[*] Waiting for emulator to boot..."
    adb wait-for-device
    sleep 20
    adb root
    adb remount
    
    echo "[+] Emulator launched and rooted successfully"
}

# ==== 4. SETUP MITMPROXY ====
setup_mitmproxy() {
    echo "[*] Launching mitmproxy on port $MITMPROXY_PORT..."
    nohup mitmproxy --listen-port $MITMPROXY_PORT --listen-host 0.0.0.0 > /tmp/mitmproxy.log 2>&1 &
    
    # Configure emulator proxy
    echo "[*] Setting proxy on emulator..."
    adb shell settings put global http_proxy "10.0.2.2:$MITMPROXY_PORT"
    
    echo "[+] Mitmproxy configured successfully"
}

# ==== 5. INSTALL MITM CA CERTIFICATE ====
install_ca_cert() {
    echo "[*] Installing mitmproxy CA cert in emulator system-wide..."
    CERT_SRC=~/.mitmproxy/mitmproxy-ca-cert.pem
    CERT_DER=~/.mitmproxy/mitmproxy-ca-cert.cer
    
    if [ ! -f "$CERT_SRC" ]; then
        # Generate the CA by running mitmproxy once if needed
        echo | openssl s_client -connect 127.0.0.1:$MITMPROXY_PORT > /dev/null 2>&1 || true
        sleep 5
    fi
    
    openssl x509 -inform PEM -in "$CERT_SRC" -outform DER -out "$CERT_DER"
    adb push "$CERT_DER" /sdcard/
    
    adb shell su -c "mount -o remount,rw /system"
    adb shell su -c "cp /sdcard/mitmproxy-ca-cert.cer /system/etc/security/cacerts/$(openssl x509 -inform DER -subject_hash_old -in $CERT_DER | head -1).0"
    adb shell su -c "chmod 644 /system/etc/security/cacerts/*.0"
    
    adb reboot
    echo "[*] Emulator rebooting..."
    sleep 15
    
    # Wait for device after reboot
    adb wait-for-device
    sleep 10
    
    echo "[+] CA certificate installed successfully"
}

# ==== 6. SETUP FRIDA SERVER ====
setup_frida() {
    echo "[*] Downloading and installing frida-server ($FRIDA_VER)..."
    FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-x86_64.xz"
    FRIDA_BIN="frida-server-${FRIDA_VER}-android-x86_64"
    
    cd /tmp
    wget -q "$FRIDA_URL" -O frida-server.xz
    xz -d frida-server.xz
    chmod +x "$FRIDA_BIN"
    
    adb push "$FRIDA_BIN" /data/local/tmp/
    adb shell "chmod 755 /data/local/tmp/$FRIDA_BIN"
    adb shell "pkill frida-server || true"
    adb shell "/data/local/tmp/$FRIDA_BIN &"
    
    echo "[+] Frida server installed and started on emulator"
}

# ==== 7. PRINT FINAL INSTRUCTIONS ====
print_final_instructions() {
    echo ""
    echo "==== ANDROID MITM ENVIRONMENT READY ===="
    echo ""
    echo "* Emulator ($AVD_NAME, API $API_LEVEL) is running and rooted."
    echo "* mitmproxy listening on port $MITMPROXY_PORT."
    echo "* System CA cert installed on emulator."
    echo "* Frida-server running on emulator."
    echo "* Objection CLI installed."
    echo ""
    echo "=== TO RUN YOUR APK WITH SSL PINNING BYPASS ==="
    echo ""
    echo "# 1. Install APK:"
    echo "    adb install /path/to/your.apk"
    echo ""
    echo "# 2. Run Objection to bypass SSL pinning (replace 'com.example.app'):"
    echo "    objection -g com.example.app explore"
    echo "    > android sslpinning disable"
    echo ""
    echo "# 3. Use app as normal — mitmproxy will show/intercept HTTPS traffic."
    echo ""
    echo "For more details, see the documentation in the 'docs/' directory."
}

# ==== MAIN EXECUTION ====
main() {
    print_banner
    check_environment
    install_dependencies
    setup_android_sdk
    create_and_launch_avd
    setup_mitmproxy
    install_ca_cert
    setup_frida
    print_final_instructions
}

# Execute main function
main