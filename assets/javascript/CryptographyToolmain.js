/**
 * Fernet Cryptography Studio - Core Engine & UI Logic
 * Standard: Fernet Specification (cryptography.io)
 * Format:
 *   Key: 32 bytes (16 bytes HMAC signing key + 16 bytes AES-128 encryption key), Base64URL encoded.
 *   Token: Base64URL( 0x80 (1B) || Timestamp (8B BigEndian) || IV (16B) || Ciphertext (AES-128-CBC) || HMAC-SHA256 (32B) )
 * Implementation: 100% Native Web Crypto API (Client-Side Only, Zero Network Exposure).
 */

'use strict';

/* ==========================================================================
   1. Helper Utilities (Base64URL, Binary & Hex Conversions)
   ========================================================================== */
const CryptoUtils = {
    /**
     * Converts a Uint8Array into a standard Base64URL string (RFC 4648 without padding or with padding)
     */
    uint8ArrayToBase64Url(uint8) {
        let binary = '';
        const len = uint8.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(uint8[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    },

    /**
     * Decodes a Base64 or Base64URL string into Uint8Array
     */
    base64UrlToUint8Array(base64UrlStr) {
        if (!base64UrlStr || typeof base64UrlStr !== 'string') {
            throw new Error('Input string tidak valid untuk dekode Base64.');
        }

        let base64 = base64UrlStr
            .trim()
            .replace(/-/g, '+')
            .replace(/_/g, '/');

        // Tambahkan padding '=' jika kurang
        while (base64.length % 4 !== 0) {
            base64 += '=';
        }

        try {
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes;
        } catch (e) {
            throw new Error('Format Base64URL rusak atau tidak valid.');
        }
    },

    /**
     * Converts Uint8Array to a hex string for inspection
     */
    bytesToHex(uint8) {
        return Array.from(uint8)
            .map(b => b.toString(16).padStart(2, '0'))
            .join(' ');
    },

    /**
     * Constant time comparison to prevent timing attacks
     */
    constantTimeEqual(a, b) {
        if (a.length !== b.length) return false;
        let c = 0;
        for (let i = 0; i < a.length; i++) {
            c |= a[i] ^ b[i];
        }
        return c === 0;
    },

    /**
     * Writes 64-bit integer timestamp to Uint8Array (Big Endian)
     */
    writeBigEndian64(timestampSeconds) {
        const buffer = new ArrayBuffer(8);
        const view = new DataView(buffer);
        view.setBigUint64(0, BigInt(timestampSeconds), false); // false = big endian
        return new Uint8Array(buffer);
    },

    /**
     * Reads 64-bit Big Endian integer timestamp from Uint8Array
     */
    readBigEndian64(uint8, offset = 0) {
        const view = new DataView(uint8.buffer, uint8.byteOffset + offset, 8);
        return Number(view.getBigUint64(0, false));
    }
};

/* ==========================================================================
   2. Fernet Cryptographic Engine
   ========================================================================== */
const FernetEngine = {
    FERNET_VERSION: 0x80, // 128 in decimal

    /**
     * Generates a 32-byte cryptographically secure random key
     * Encoded as Base64URL (44 chars with '=')
     */
    generateKey() {
        const rawKey = new Uint8Array(32);
        window.crypto.getRandomValues(rawKey);
        return CryptoUtils.uint8ArrayToBase64Url(rawKey);
    },

    /**
     * Validates and decomposes a 32-byte Fernet key
     * Returns: { signingKey: Uint8Array(16), encryptionKey: Uint8Array(16) }
     */
    decomposeKey(base64UrlKey) {
        const keyBytes = CryptoUtils.base64UrlToUint8Array(base64UrlKey);
        if (keyBytes.length !== 32) {
            throw new Error(`Panjang kunci tidak valid: harus tepat 32 bytes (diterima ${keyBytes.length} bytes).`);
        }

        return {
            raw: keyBytes,
            signingKey: keyBytes.slice(0, 16),
            encryptionKey: keyBytes.slice(16, 32)
        };
    },

    /**
     * Encrypts plaintext string into Fernet token
     */
    async encrypt(plaintext, base64UrlKey) {
        if (!plaintext) {
            throw new Error('Pesan plaintext tidak boleh kosong.');
        }
        const { signingKey, encryptionKey } = this.decomposeKey(base64UrlKey);

        // 1. Current timestamp in seconds
        const currentTimestampSec = Math.floor(Date.now() / 1000);
        const timestampBytes = CryptoUtils.writeBigEndian64(currentTimestampSec);

        // 2. 16-byte random IV using CSPRNG
        const iv = new Uint8Array(16);
        window.crypto.getRandomValues(iv);

        // 3. Import AES-CBC Key
        const cryptoAesKey = await window.crypto.subtle.importKey(
            'raw',
            encryptionKey,
            { name: 'AES-CBC' },
            false,
            ['encrypt']
        );

        // 4. Encrypt plaintext (Web Crypto Subtle automatically handles PKCS#7 padding for AES-CBC)
        const encoder = new TextEncoder();
        const plaintextBytes = encoder.encode(plaintext);

        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: iv },
            cryptoAesKey,
            plaintextBytes
        );
        const ciphertextBytes = new Uint8Array(ciphertextBuffer);

        // 5. Construct Basic Payload: Version (1B) || Timestamp (8B) || IV (16B) || Ciphertext (var)
        const basicPartsLen = 1 + 8 + 16 + ciphertextBytes.length;
        const basicParts = new Uint8Array(basicPartsLen);

        basicParts[0] = this.FERNET_VERSION;
        basicParts.set(timestampBytes, 1);
        basicParts.set(iv, 9);
        basicParts.set(ciphertextBytes, 25);

        // 6. Compute HMAC-SHA256 over basicParts using signingKey
        const cryptoHmacKey = await window.crypto.subtle.importKey(
            'raw',
            signingKey,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const hmacSignatureBuffer = await window.crypto.subtle.sign(
            'HMAC',
            cryptoHmacKey,
            basicParts
        );
        const hmacSignature = new Uint8Array(hmacSignatureBuffer);

        // 7. Combine: basicParts || HMAC (32B)
        const tokenBytes = new Uint8Array(basicParts.length + hmacSignature.length);
        tokenBytes.set(basicParts, 0);
        tokenBytes.set(hmacSignature, basicParts.length);

        // 8. Return Base64URL string
        return CryptoUtils.uint8ArrayToBase64Url(tokenBytes);
    },

    /**
     * Decrypts Fernet token into plaintext string
     */
    async decrypt(tokenStr, base64UrlKey, maxAgeSeconds = null) {
        if (!tokenStr) {
            throw new Error('Token Fernet tidak boleh kosong.');
        }
        const { signingKey, encryptionKey } = this.decomposeKey(base64UrlKey);
        const tokenBytes = CryptoUtils.base64UrlToUint8Array(tokenStr);

        // Minimal length: Version (1) + Timestamp (8) + IV (16) + Ciphertext (min 16 for PKCS#7 block) + HMAC (32) = 73 bytes
        if (tokenBytes.length < 73) {
            throw new Error('Token terlalu pendek atau bukan token Fernet yang valid.');
        }

        // 1. Verify Version
        if (tokenBytes[0] !== this.FERNET_VERSION) {
            throw new Error(`Versi token tidak didukung: 0x${tokenBytes[0].toString(16)}. Diharapkan 0x80.`);
        }

        // 2. Verify HMAC Signature
        const basicParts = tokenBytes.slice(0, tokenBytes.length - 32);
        const receivedHmac = tokenBytes.slice(tokenBytes.length - 32);

        const cryptoHmacKey = await window.crypto.subtle.importKey(
            'raw',
            signingKey,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const expectedHmacBuffer = await window.crypto.subtle.sign(
            'HMAC',
            cryptoHmacKey,
            basicParts
        );
        const expectedHmac = new Uint8Array(expectedHmacBuffer);

        if (!CryptoUtils.constantTimeEqual(receivedHmac, expectedHmac)) {
            throw new Error('Verifikasi HMAC Gagal! Token telah dirusak (tampered) atau kunci enkripsi salah.');
        }

        // 3. Extract & Check Timestamp / TTL
        const tokenTimestampSec = CryptoUtils.readBigEndian64(tokenBytes, 1);
        const nowSec = Math.floor(Date.now() / 1000);

        if (maxAgeSeconds !== null && maxAgeSeconds > 0) {
            if (nowSec - tokenTimestampSec > maxAgeSeconds) {
                throw new Error(`Token telah kadaluarsa (TTL melampaui batas ${maxAgeSeconds} detik).`);
            }
        }

        // 4. Extract IV & Ciphertext
        const iv = tokenBytes.slice(9, 25);
        const ciphertext = tokenBytes.slice(25, tokenBytes.length - 32);

        // 5. Decrypt AES-128-CBC
        const cryptoAesKey = await window.crypto.subtle.importKey(
            'raw',
            encryptionKey,
            { name: 'AES-CBC' },
            false,
            ['decrypt']
        );

        try {
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: iv },
                cryptoAesKey,
                ciphertext
            );
            const decoder = new TextDecoder('utf-8', { fatal: true });
            return decoder.decode(decryptedBuffer);
        } catch (e) {
            throw new Error('Gagal mendeskripsi muatan (Padding atau Ciphertext korup).');
        }
    },

    /**
     * Dissects a token into structural components for educational inspection
     */
    dissectToken(tokenStr) {
        const tokenBytes = CryptoUtils.base64UrlToUint8Array(tokenStr);
        if (tokenBytes.length < 57) { // 1 + 8 + 16 + 0 + 32
            throw new Error('Token terlalu pendek untuk dianalisis.');
        }

        const version = tokenBytes[0];
        const timestamp = CryptoUtils.readBigEndian64(tokenBytes, 1);
        const iv = tokenBytes.slice(9, 25);
        const ciphertext = tokenBytes.slice(25, tokenBytes.length - 32);
        const hmac = tokenBytes.slice(tokenBytes.length - 32);

        const date = new Date(timestamp * 1000);

        return {
            versionHex: `0x${version.toString(16).toUpperCase()}`,
            timestampRaw: timestamp,
            timestampReadable: `${date.toLocaleDateString('id-ID')} ${date.toLocaleTimeString('id-ID')} (${Math.floor((Date.now() - date.getTime()) / 1000)} detik yang lalu)`,
            ivHex: CryptoUtils.bytesToHex(iv),
            ciphertextLen: `${ciphertext.length} bytes`,
            ciphertextHex: CryptoUtils.bytesToHex(ciphertext.slice(0, 16)) + (ciphertext.length > 16 ? '...' : ''),
            hmacHex: CryptoUtils.bytesToHex(hmac)
        };
    }
};

/* ==========================================================================
   3. Sensitive Data Keywords & Guardian Heuristic
   ========================================================================== */
const SensitiveGuardian = {
    keywords: [
        'password', 'kata sandi', 'pin', 'rahasia', 'token', 'secret',
        'credit card', 'kartu kredit', 'cvv', 'nik', 'ktp', 'api_key', 'apikey'
    ],

    check(text) {
        if (!text) return false;
        const lower = text.toLowerCase();
        return this.keywords.some(word => lower.includes(word));
    }
};

/* ==========================================================================
   4. UI Controller & Event Wiring
   ========================================================================== */
document.addEventListener('DOMContentLoaded', () => {
    // --- Elements: Theme ---
    const themeToggleBtn = document.getElementById('themeToggleBtn');
    const htmlEl = document.documentElement;

    // --- Elements: Key Management ---
    const fernetKeyInput = document.getElementById('fernetKeyInput');
    const toggleKeyVisibilityBtn = document.getElementById('toggleKeyVisibilityBtn');
    const copyKeyBtn = document.getElementById('copyKeyBtn');
    const generateKeyBtn = document.getElementById('generateKeyBtn');
    const inspectKeyBtn = document.getElementById('inspectKeyBtn');
    const keyStatusBadge = document.getElementById('keyStatusBadge');
    const keyInspectorPanel = document.getElementById('keyInspectorPanel');
    const inspectSigningKey = document.getElementById('inspectSigningKey');
    const inspectEncryptionKey = document.getElementById('inspectEncryptionKey');

    // --- Elements: Tabs ---
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    // --- Elements: Encryption ---
    const plaintextInput = document.getElementById('plaintextInput');
    const plaintextCount = document.getElementById('plaintextCount');
    const doEncryptBtn = document.getElementById('doEncryptBtn');
    const clearEncryptBtn = document.getElementById('clearEncryptBtn');
    const encryptedOutput = document.getElementById('encryptedOutput');
    const copyCiphertextBtn = document.getElementById('copyCiphertextBtn');
    const sensitiveAlert = document.getElementById('sensitiveAlert');

    // --- Elements: Decryption ---
    const ciphertextInput = document.getElementById('ciphertextInput');
    const pasteFromEncryptBtn = document.getElementById('pasteFromEncryptBtn');
    const enforceTTLCheckbox = document.getElementById('enforceTTLCheckbox');
    const ttlWrapper = document.getElementById('ttlWrapper');
    const ttlSecondsInput = document.getElementById('ttlSecondsInput');
    const doDecryptBtn = document.getElementById('doDecryptBtn');
    const clearDecryptBtn = document.getElementById('clearDecryptBtn');
    const decryptedOutput = document.getElementById('decryptedOutput');
    const copyPlaintextBtn = document.getElementById('copyPlaintextBtn');

    // --- Elements: Token Inspector ---
    const inspectTokenInput = document.getElementById('inspectTokenInput');
    const runInspectTokenBtn = document.getElementById('runInspectTokenBtn');
    const tokenDissectionResult = document.getElementById('tokenDissectionResult');
    const tokVersion = document.getElementById('tokVersion');
    const tokTimestamp = document.getElementById('tokTimestamp');
    const tokTimeReadable = document.getElementById('tokTimeReadable');
    const tokIV = document.getElementById('tokIV');
    const tokCipherLen = document.getElementById('tokCipherLen');
    const tokHMAC = document.getElementById('tokHMAC');

    // --- Toast Notification ---
    const toast = document.getElementById('toast');
    let toastTimeout = null;

    function showToast(message, type = 'info') {
        if (!toast) return;
        clearTimeout(toastTimeout);
        toast.textContent = message;
        toast.className = 'toast show';
        if (type === 'error') toast.classList.add('toast-error');
        if (type === 'success') toast.classList.add('toast-success');

        toastTimeout = setTimeout(() => {
            toast.className = 'toast';
        }, 3200);
    }

    // --- Clipboard Helper ---
    async function copyToClipboard(text, successMsg) {
        if (!text) {
            showToast('Tidak ada teks untuk disalin!', 'error');
            return;
        }
        try {
            await navigator.clipboard.writeText(text);
            showToast(successMsg, 'success');
        } catch (err) {
            // Fallback
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            showToast(successMsg, 'success');
        }
    }

    // --- 1. Theme Management ---
    const savedTheme = localStorage.getItem('fernet_studio_theme') || 'dark';
    htmlEl.setAttribute('data-theme', savedTheme);

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            const currentTheme = htmlEl.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            htmlEl.setAttribute('data-theme', newTheme);
            localStorage.setItem('fernet_studio_theme', newTheme);
            showToast(`Mode tema diubah ke: ${newTheme === 'dark' ? 'Gelap' : 'Terang'}`);
        });
    }

    // --- 2. Key Management ---
    function updateKeyBadgeStatus() {
        const key = fernetKeyInput.value.trim();
        if (!key) {
            keyStatusBadge.textContent = 'Kunci Belum Dibuat';
            keyStatusBadge.className = 'badge';
            keyInspectorPanel.classList.add('hidden');
            return;
        }
        try {
            FernetEngine.decomposeKey(key);
            keyStatusBadge.textContent = 'Kunci Valid (32 Bytes)';
            keyStatusBadge.className = 'badge badge-success';
        } catch (e) {
            keyStatusBadge.textContent = 'Kunci Tidak Valid';
            keyStatusBadge.className = 'badge badge-warning';
            keyInspectorPanel.classList.add('hidden');
        }
    }

    if (generateKeyBtn) {
        generateKeyBtn.addEventListener('click', () => {
            const newKey = FernetEngine.generateKey();
            fernetKeyInput.value = newKey;
            updateKeyBadgeStatus();
            showToast('Kunci Fernet 256-bit baru berhasil dibuat (CSPRNG)!', 'success');
            
            // Otomatis bedah struktur jika panel sedang terbuka
            if (!keyInspectorPanel.classList.contains('hidden')) {
                inspectKeyStructure();
            }
        });
    }

    if (toggleKeyVisibilityBtn) {
        toggleKeyVisibilityBtn.addEventListener('click', () => {
            const isPassword = fernetKeyInput.type === 'password';
            fernetKeyInput.type = isPassword ? 'text' : 'password';
            toggleKeyVisibilityBtn.textContent = isPassword ? 'Sembunyikan' : 'Lihat';
        });
    }

    if (copyKeyBtn) {
        copyKeyBtn.addEventListener('click', () => {
            copyToClipboard(fernetKeyInput.value.trim(), 'Kunci Fernet berhasil disalin!');
        });
    }

    function inspectKeyStructure() {
        const key = fernetKeyInput.value.trim();
        try {
            const { signingKey, encryptionKey } = FernetEngine.decomposeKey(key);
            inspectSigningKey.textContent = CryptoUtils.bytesToHex(signingKey);
            inspectEncryptionKey.textContent = CryptoUtils.bytesToHex(encryptionKey);
            keyInspectorPanel.classList.remove('hidden');
        } catch (e) {
            showToast(e.message, 'error');
            keyInspectorPanel.classList.add('hidden');
        }
    }

    if (inspectKeyBtn) {
        inspectKeyBtn.addEventListener('click', () => {
            if (keyInspectorPanel.classList.contains('hidden')) {
                inspectKeyStructure();
            } else {
                keyInspectorPanel.classList.add('hidden');
            }
        });
    }

    if (fernetKeyInput) {
        fernetKeyInput.addEventListener('input', () => {
            updateKeyBadgeStatus();
        });
    }

    // --- 3. Tabs Navigation ---
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            tabBtns.forEach(b => {
                b.classList.remove('active');
                b.setAttribute('aria-selected', 'false');
            });
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            btn.setAttribute('aria-selected', 'true');
            const targetContent = document.getElementById(targetId);
            if (targetContent) targetContent.classList.add('active');
        });
    });

    // --- 4. Encryption Flow ---
    if (plaintextInput) {
        plaintextInput.addEventListener('input', () => {
            const text = plaintextInput.value;
            plaintextCount.textContent = `${text.length} karakter`;

            // Cek peringatan teks sensitif
            if (SensitiveGuardian.check(text)) {
                sensitiveAlert.classList.add('visible');
            } else {
                sensitiveAlert.classList.remove('visible');
            }
        });
    }

    if (doEncryptBtn) {
        doEncryptBtn.addEventListener('click', async () => {
            const text = plaintextInput.value;
            const key = fernetKeyInput.value.trim();

            if (!key) {
                showToast('Harap buat atau masukkan kunci Fernet terlebih dahulu!', 'error');
                fernetKeyInput.focus();
                return;
            }
            if (!text) {
                showToast('Ketikkan pesan teks yang ingin dienkripsi!', 'error');
                plaintextInput.focus();
                return;
            }

            try {
                const token = await FernetEngine.encrypt(text, key);
                encryptedOutput.value = token;
                showToast('Pesan berhasil dienkripsi ke format Fernet!', 'success');
            } catch (err) {
                showToast(err.message, 'error');
            }
        });
    }

    if (clearEncryptBtn) {
        clearEncryptBtn.addEventListener('click', () => {
            plaintextInput.value = '';
            encryptedOutput.value = '';
            plaintextCount.textContent = '0 karakter';
            sensitiveAlert.classList.remove('visible');
        });
    }

    if (copyCiphertextBtn) {
        copyCiphertextBtn.addEventListener('click', () => {
            copyToClipboard(encryptedOutput.value.trim(), 'Token ciphertext berhasil disalin!');
        });
    }

    // --- 5. Decryption Flow ---
    if (pasteFromEncryptBtn) {
        pasteFromEncryptBtn.addEventListener('click', () => {
            const token = encryptedOutput.value.trim();
            if (!token) {
                showToast('Belum ada token dari hasil enkripsi!', 'error');
                return;
            }
            ciphertextInput.value = token;
            showToast('Token hasil enkripsi ditempel.', 'info');
        });
    }

    if (enforceTTLCheckbox) {
        enforceTTLCheckbox.addEventListener('change', () => {
            if (enforceTTLCheckbox.checked) {
                ttlWrapper.classList.remove('hidden');
            } else {
                ttlWrapper.classList.add('hidden');
            }
        });
    }

    if (doDecryptBtn) {
        doDecryptBtn.addEventListener('click', async () => {
            const token = ciphertextInput.value.trim();
            const key = fernetKeyInput.value.trim();

            if (!key) {
                showToast('Masukkan kunci Fernet yang sesuai!', 'error');
                fernetKeyInput.focus();
                return;
            }
            if (!token) {
                showToast('Masukkan token Fernet yang akan didekripsi!', 'error');
                ciphertextInput.focus();
                return;
            }

            const maxAge = enforceTTLCheckbox.checked ? parseInt(ttlSecondsInput.value, 10) : null;

            try {
                const plaintext = await FernetEngine.decrypt(token, key, maxAge);
                decryptedOutput.value = plaintext;
                showToast('Token berhasil didekripsi & lolos verifikasi otentikasi!', 'success');
            } catch (err) {
                decryptedOutput.value = '';
                showToast(err.message, 'error');
            }
        });
    }

    if (clearDecryptBtn) {
        clearDecryptBtn.addEventListener('click', () => {
            ciphertextInput.value = '';
            decryptedOutput.value = '';
        });
    }

    if (copyPlaintextBtn) {
        copyPlaintextBtn.addEventListener('click', () => {
            copyToClipboard(decryptedOutput.value, 'Pesan hasil dekripsi berhasil disalin!');
        });
    }

    // --- 6. Token Inspector Flow ---
    if (runInspectTokenBtn) {
        runInspectTokenBtn.addEventListener('click', () => {
            const token = inspectTokenInput.value.trim();
            if (!token) {
                showToast('Masukkan token Fernet untuk dianalisis!', 'error');
                return;
            }

            try {
                const analysis = FernetEngine.dissectToken(token);
                tokVersion.textContent = analysis.versionHex;
                tokTimestamp.textContent = analysis.timestampRaw;
                tokTimeReadable.textContent = analysis.timestampReadable;
                tokIV.textContent = analysis.ivHex;
                tokCipherLen.textContent = `${analysis.ciphertextLen} (${analysis.ciphertextHex})`;
                tokHMAC.textContent = analysis.hmacHex;

                tokenDissectionResult.classList.remove('hidden');
                showToast('Analisis token selesai!', 'success');
            } catch (e) {
                tokenDissectionResult.classList.add('hidden');
                showToast(e.message, 'error');
            }
        });
    }

    // Inisialisasi: otomatis generate sebuah kunci pertama kali untuk kenyamanan pengguna
    const initialKey = FernetEngine.generateKey();
    fernetKeyInput.value = initialKey;
    updateKeyBadgeStatus();
});
