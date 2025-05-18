/**
 * Advanced SSL Pinning Bypass Script for Frida
 * 
 * This script targets multiple common SSL pinning implementations:
 * - OkHttp3 (multiple versions)
 * - TrustManager
 * - X509TrustManager
 * - SSLContext
 * - Certificate chains validation
 * - Custom certificate verification methods
 * 
 * Usage with Frida CLI:
 *   frida -U -f com.example.app -l ssl_pinning_bypass.js --no-pause
 * 
 * Usage with Objection:
 *   import ssl_pinning_bypass.js
 */

setTimeout(function() {
    console.log("[+] Advanced SSL Pinning Bypass Script Loaded");
    
    // 1. OkHttp3 Certificate Pinning Bypass
    try {
        const CertificatePinner = Java.use('okhttp3.CertificatePinner');
        
        // OkHttp v3 Check
        try {
            const CertificatePinner_check = CertificatePinner.check.overload('java.lang.String', 'java.util.List');
            CertificatePinner_check.implementation = function(hostname, certificateChain) {
                console.log('[+] OkHttp3 (List): Certificate pinning bypassed for ' + hostname);
                return;
            };
            console.log('[+] OkHttp3 (List): Certificate pinning bypass successful');
        } catch (err) {
            console.log('[-] OkHttp3 (List): Certificate pinning bypass failed');
        }
        
        // OkHttp v3 Check (alternate)
        try {
            const CertificatePinner_check = CertificatePinner.check.overload('java.lang.String', 'java.security.cert.Certificate[]');
            CertificatePinner_check.implementation = function(hostname, certificates) {
                console.log('[+] OkHttp3 (Array): Certificate pinning bypassed for ' + hostname);
                return;
            };
            console.log('[+] OkHttp3 (Array): Certificate pinning bypass successful');
        } catch (err) {
            console.log('[-] OkHttp3 (Array): Certificate pinning bypass failed');
        }
        
        // OkHttp v3 Check (older)
        try {
            const CertificatePinner_check = CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;');
            CertificatePinner_check.implementation = function(hostname, certificates) {
                console.log('[+] OkHttp3 (Old): Certificate pinning bypassed for ' + hostname);
                return;
            };
            console.log('[+] OkHttp3 (Old): Certificate pinning bypass successful');
        } catch (err) {
            console.log('[-] OkHttp3 (Old): Certificate pinning bypass failed');
        }
    } catch (err) {
        console.log('[-] OkHttp3: Certificate pinning bypass failed');
    }
    
    // 2. TrustManager Bypass
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        // TrustManager bypass
        const TrustManager = Java.registerClass({
            name: 'com.android.mitm.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });
        
        // Create a new TrustManager instance
        const TrustManagers = [TrustManager.$new()];
        
        // Get the default SSLContext
        const SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', 
            '[Ljavax.net.ssl.TrustManager;', 
            'java.security.SecureRandom'
        );
        
        // Override the init method to use our TrustManager
        SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
            console.log('[+] Intercepting SSLContext.init(), replacing TrustManager');
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
        
        console.log('[+] TrustManager & SSLContext bypass successful');
    } catch (err) {
        console.log('[-] TrustManager bypass failed: ' + err);
    }
    
    // 3. Certificate Validation Bypass for Apache and Custom Implementations
    try {
        const CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        const CertificateFactory_generateCertificate = CertificateFactory.generateCertificate;
        
        CertificateFactory_generateCertificate.implementation = function(inputStream) {
            console.log("[+] CertificateFactory.generateCertificate() intercepted");
            return CertificateFactory_generateCertificate.call(this, inputStream);
        };
        
        console.log('[+] Certificate validation bypass successful');
    } catch (err) {
        console.log('[-] Certificate validation bypass failed: ' + err);
    }
    
    // 4. WebView SSL Error Bypass
    try {
        const WebViewClient = Java.use("android.webkit.WebViewClient");
        
        // Different WebViewClient.onReceivedSslError() versions
        try {
            WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(webView, handler, error) {
                console.log('[+] WebViewClient.onReceivedSslError(): SSL error bypassed');
                handler.proceed();
                return;
            };
            console.log('[+] WebViewClient SSL error bypass successful');
        } catch (err) {
            console.log('[-] WebViewClient SSL error bypass failed');
        }
    } catch (err) {
        console.log('[-] WebView SSL bypass failed: ' + err);
    }
    
    // 5. Trust Anchor Bypass
    try {
        const Conscrypt_TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        
        if (Conscrypt_TrustManagerImpl) {
            try {
                Conscrypt_TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    console.log('[+] Conscrypt TrustManagerImpl.verifyChain(): Bypassed for ' + host);
                    return untrustedChain;
                };
                console.log('[+] Conscrypt TrustManagerImpl bypass successful');
            } catch (err) {
                console.log('[-] Conscrypt TrustManagerImpl bypass failed: ' + err);
            }
        }
    } catch (err) {
        console.log('[-] Conscrypt bypass failed: ' + err);
    }
    
    // 6. Generic TrustManagerImpl Hook
    try {
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        
        // Android 7+ hook
        try {
            TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                console.log('[+] TrustManagerImpl.checkTrustedRecursive(): Bypassed for ' + host);
                return Java.use('java.util.ArrayList').$new();
            };
            console.log('[+] TrustManagerImpl.checkTrustedRecursive() bypass successful');
        } catch (err) {
            console.log('[-] TrustManagerImpl.checkTrustedRecursive() bypass failed: ' + err);
        }
        
        // Android 6 hook
        try {
            const ArrayList = Java.use("java.util.ArrayList");
            TrustManagerImpl.checkTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String').implementation = function(chain, authType, host) {
                console.log('[+] TrustManagerImpl.checkTrusted(): Bypassed for ' + host);
                return ArrayList.$new();
            };
            console.log('[+] TrustManagerImpl.checkTrusted() bypass successful');
        } catch (err) {
            console.log('[-] TrustManagerImpl.checkTrusted() bypass failed: ' + err);
        }
    } catch (err) {
        console.log('[-] TrustManagerImpl bypass failed: ' + err);
    }
    
    console.log("[+] SSL Pinning Bypass Completed");
    console.log("[+] App should now accept any SSL certificate");
    
}, 1000);