# Scripts Directory

This directory contains various scripts for the Android MITM SSL Interceptor.

## Frida Scripts

- `ssl_pinning_bypass.js` - Advanced SSL pinning bypass script targeting multiple implementations

## Helper Scripts

- `install_dependencies.sh` - Script to install required dependencies
- `launch_emulator.sh` - Script to launch configured emulator
- `setup_certificates.sh` - Script to set up CA certificates

## Usage

Most of these scripts are called by the main `setup_android_mitm.sh` script. However, they can also be used independently if needed.

For the Frida scripts, they can be used directly with Frida or through Objection:

```bash
# Using with Frida
frida -U -f com.example.app -l frida_scripts/ssl_pinning_bypass.js --no-pause

# Using with Objection
objection -g com.example.app explore
# Inside objection console
import ssl_pinning_bypass.js
```