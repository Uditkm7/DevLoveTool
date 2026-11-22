package com.developer.love.tool.keystore;

import android.content.Context;

import com.developer.love.tool.core.AppConstants;
import com.developer.love.tool.core.AppUtils;
import com.developer.love.tool.storage.FileManager;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class KeystoreManager {

    private static final int JKS_MAGIC = 0xFEEDFEED;
    private static final long MAX_KEYSTORE_SIZE_BYTES = 20L * 1024L * 1024L;

    public static class KeystoreResult {
        public boolean isSuccess;
        public String fileName;
        public String filePath;
        public String format;
        public String alias;
        public int validityYears;
        public String sha256;
        public String subject;
        public long fileSize;
        public String errorMessage;
    }

    public interface OnKeystoreGeneratedListener {
        void onCompleted(KeystoreResult result);
    }

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    public void generateKeystoreAsync(
            Context context,
            String fileNameInput,
            String keystorePassword,
            String alias,
            String keyPassword,
            CertificateGenerator.CertParams certParams,
            String format,
            OnKeystoreGeneratedListener listener
    ) {
        executor.execute(() -> {
            KeystoreResult result = new KeystoreResult();
            char[] ksPassChars = keystorePassword.toCharArray();
            char[] keyPassChars = keyPassword.toCharArray();

            try {
                String cleanName = fileNameInput.trim();
                String ext = format.equalsIgnoreCase(AppConstants.FORMAT_JKS) ? ".jks" : ".p12";
                if (!cleanName.toLowerCase().endsWith(".jks")
                        && !cleanName.toLowerCase().endsWith(".p12")
                        && !cleanName.toLowerCase().endsWith(".keystore")) {
                    cleanName = cleanName + ext;
                }

                File destDir = FileManager.getKeystoresDir(context);
                File keystoreFile = new File(destDir, cleanName);

                KeyPair keyPair = CertificateGenerator.generateRSAKeyPair(2048);
                X509Certificate cert = CertificateGenerator.generateSelfSignedCertificate(keyPair, certParams);

                KeyStore ks;
                String ksType = format.equalsIgnoreCase(AppConstants.FORMAT_JKS) ? "JKS" : "PKCS12";
                try {
                    ks = KeyStore.getInstance(ksType);
                    ks.load(null, null);
                } catch (Exception e) {
                    ksType = "PKCS12";
                    ks = KeyStore.getInstance(ksType);
                    ks.load(null, null);
                }

                Certificate[] chain = new Certificate[]{cert};
                ks.setKeyEntry(alias, keyPair.getPrivate(), keyPassChars, chain);

                try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
                    ks.store(fos, ksPassChars);
                    fos.flush();
                }

                KeyStore verifyKs = KeyStore.getInstance(ksType);
                try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                    verifyKs.load(fis, ksPassChars);
                }

                if (!verifyKs.containsAlias(alias)) {
                    throw new IllegalStateException("Verification failed: alias '" + alias + "' was not found in stored keystore.");
                }

                Certificate verifyCert = verifyKs.getCertificate(alias);
                if (verifyCert == null) {
                    throw new IllegalStateException("Verification failed: certificate for alias '" + alias + "' could not be retrieved.");
                }

                byte[] encodedCert = verifyCert.getEncoded();
                String sha256 = AppUtils.getFingerprint(encodedCert, "SHA-256");

                result.isSuccess = true;
                result.fileName = keystoreFile.getName();
                result.filePath = keystoreFile.getAbsolutePath();
                result.format = ksType;
                result.alias = alias;
                result.validityYears = certParams.validityYears > 0 ? certParams.validityYears : 100;
                result.sha256 = sha256;
                result.subject = cert.getSubjectX500Principal().getName();
                result.fileSize = keystoreFile.length();

            } catch (Exception e) {
                result.isSuccess = false;
                result.errorMessage = "Keystore generation failed: " + e.getMessage();
            } finally {
                Arrays.fill(ksPassChars, '0');
                Arrays.fill(keyPassChars, '0');
            }

            if (listener != null) {
                listener.onCompleted(result);
            }
        });
    }

    public static boolean isJksBinaryFormat(File file) {
        if (file == null || !file.exists() || file.length() < 8) return false;
        try (DataInputStream dis = new DataInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            return dis.readInt() == JKS_MAGIC;
        } catch (Exception e) {
            return false;
        }
    }

    public static KeyStore loadKeystore(File file, String password) throws Exception {
        return loadKeystoreForSigning(file, password, null, password);
    }

    /**
     * Loads PKCS12, BKS (Sketchware/Android), or Sun JKS (0xFEEDFEED, even on Android devices
     * that lack a native JKS provider) into an active KeyStore instance.
     */
    public static KeyStore loadKeystoreForSigning(
            File file,
            String ksPassword,
            String targetAlias,
            String keyPassword
    ) throws Exception {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new IOException("Keystore file not found.");
        }
        if (file.length() > MAX_KEYSTORE_SIZE_BYTES) {
            throw new IOException("Keystore file exceeds 20 MB limit.");
        }
        char[] ksPass = ksPassword != null ? ksPassword.toCharArray() : null;
        char[] keyPass = keyPassword != null ? keyPassword.toCharArray() : ksPass;
        Exception lastErr = null;
        try {
            // 1. If binary header is JKS (0xFEEDFEED), try platform JKS first, then Pure Java JKS fallback
            if (isJksBinaryFormat(file)) {
                try {
                    KeyStore ks = KeyStore.getInstance("JKS");
                    try (FileInputStream fis = new FileInputStream(file)) {
                        ks.load(fis, ksPass);
                    }
                    return ks;
                } catch (Exception jksPlatformErr) {
                    return loadJksPureJava(file, ksPass, targetAlias, keyPass);
                }
            }

            // 2. Try PKCS12 (standard on Android Studio, Java 9+, DevLoveTool)
            try {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(file)) {
                    ks.load(fis, ksPass);
                }
                return ks;
            } catch (Exception e) {
                lastErr = e;
            }

            // 3. Try BKS (BouncyCastle KeyStore - common in Sketchware / Android tools)
            try {
                KeyStore ks = KeyStore.getInstance("BKS");
                try (FileInputStream fis = new FileInputStream(file)) {
                    ks.load(fis, ksPass);
                }
                return ks;
            } catch (Exception e) {
                if (lastErr == null) {
                    lastErr = e;
                }
            }

            // 4. Fallback to platform default KeyStore type only if previous errors were not wrong-password errors
            try {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                try (FileInputStream fis = new FileInputStream(file)) {
                    ks.load(fis, ksPass);
                }
                return ks;
            } catch (Exception defaultErr) {
                throw lastErr != null ? lastErr : defaultErr;
            }
        } finally {
            if (ksPass != null) Arrays.fill(ksPass, '0');
            if (keyPass != null) Arrays.fill(keyPass, '0');
        }
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    /**
     * Extracts aliases from JKS, PKCS12, or BKS keystores.
     * - For Sun JKS (0xFEEDFEED): extracts aliases immediately without needing a password.
     * - For encrypted PKCS12/BKS: when a non-empty password is provided, validates ONLY that
     *   password so live password typing stays fast and responsive.
     */
    public static List<String> extractAliases(File file, String password) {
        Set<String> aliasSet = new LinkedHashSet<>();
        if (file == null || !file.exists()) return new ArrayList<>();

        // 1. Pure-Java JKS binary parser (works without password on 0xFEEDFEED JKS files)
        List<String> jksAliases = extractAliasesFromJksBinary(file);
        aliasSet.addAll(jksAliases);
        if (!aliasSet.isEmpty()) {
            return new ArrayList<>(aliasSet);
        }

        // 2. If user supplied a password, test ONLY that exact password (fast, no wasted PBKDF2 loops)
        if (password != null && !password.isEmpty()) {
            try {
                KeyStore ks = loadKeystore(file, password);
                collectAliases(ks, aliasSet);
            } catch (Exception ignored) {}
            return new ArrayList<>(aliasSet);
        }

        // 3. Password is empty: try passwordless/common defaults
        try {
            KeyStore ks = loadKeystore(file, null);
            collectAliases(ks, aliasSet);
            if (!aliasSet.isEmpty()) return new ArrayList<>(aliasSet);
        } catch (Exception ignored) {}

        String[] fallbackPasswords = {"", "android"};
        for (String pass : fallbackPasswords) {
            try {
                KeyStore ks = loadKeystore(file, pass);
                collectAliases(ks, aliasSet);
                if (!aliasSet.isEmpty()) return new ArrayList<>(aliasSet);
            } catch (Exception ignored) {}
        }

        return new ArrayList<>(aliasSet);
    }

    private static void collectAliases(KeyStore ks, Set<String> aliasSet) throws Exception {
        Enumeration<String> enumeration = ks.aliases();
        while (enumeration.hasMoreElements()) {
            String a = enumeration.nextElement();
            if (a != null && !a.trim().isEmpty()) {
                aliasSet.add(a);
            }
        }
    }

    /**
     * Pure Java loader for Sun JKS (0xFEEDFEED) files when running on Android devices
     * where the "JKS" KeyStore provider is not registered in the OS security providers.
     */
    public static KeyStore loadJksPureJava(File file, char[] ksPass, String targetAlias, char[] keyPass) throws Exception {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new IOException("Keystore file not found.");
        }
        long len = file.length();
        if (len < 32) {
            throw new IOException("Invalid JKS file (too short).");
        }
        if (len > MAX_KEYSTORE_SIZE_BYTES) {
            throw new IOException("Keystore file exceeds 20 MB limit.");
        }
        byte[] allBytes;
        try (FileInputStream fis = new FileInputStream(file)) {
            allBytes = new byte[(int) len];
            int read = 0;
            while (read < allBytes.length) {
                int r = fis.read(allBytes, read, allBytes.length - read);
                if (r < 0) break;
                read += r;
            }
            if (read != allBytes.length) {
                throw new EOFException("Unexpected end of JKS file.");
            }
        }

        // Verify store integrity SHA-1 digest (trailing 20 bytes) when store password is supplied
        if (ksPass != null) {
            int bodyLen = allBytes.length - 20;
            MessageDigest md = getPreKeyedJksDigest(ksPass);
            md.update(allBytes, 0, bodyLen);
            byte[] expectedDigest = md.digest();
            byte[] actualDigest = Arrays.copyOfRange(allBytes, bodyLen, allBytes.length);
            if (!MessageDigest.isEqual(expectedDigest, actualDigest)) {
                throw new IOException("Keystore tampered with, or password was incorrect");
            }
        }

        KeyStore outKs = KeyStore.getInstance("PKCS12");
        outKs.load(null, null);

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(allBytes, 0, allBytes.length - 20));
        int magic = dis.readInt();
        if (magic != JKS_MAGIC) {
            throw new IOException("Not a valid JKS file.");
        }
        int version = dis.readInt();
        if (version != 1 && version != 2) {
            throw new IOException("Unsupported JKS version: " + version);
        }
        int count = dis.readInt();
        if (count < 0 || count > 1000) {
            throw new IOException("Invalid JKS entry count: " + count);
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        for (int i = 0; i < count; i++) {
            int tag = dis.readInt();
            if (tag == 1) {
                String alias = dis.readUTF();
                dis.readLong(); // timestamp
                int keyLen = dis.readInt();
                if (keyLen < 0 || keyLen > allBytes.length) {
                    throw new IOException("Invalid JKS key blob length: " + keyLen);
                }
                byte[] protectedKey = new byte[keyLen];
                dis.readFully(protectedKey);

                int chainLen = dis.readInt();
                if (chainLen < 0 || chainLen > 100) {
                    throw new IOException("Invalid JKS certificate chain length: " + chainLen);
                }
                Certificate[] chain = new Certificate[chainLen];
                for (int c = 0; c < chainLen; c++) {
                    if (version == 2) {
                        dis.readUTF();
                    }
                    int certLen = dis.readInt();
                    if (certLen < 0 || certLen > allBytes.length) {
                        throw new IOException("Invalid JKS certificate length: " + certLen);
                    }
                    byte[] certBytes = new byte[certLen];
                    dis.readFully(certBytes);
                    chain[c] = cf.generateCertificate(new ByteArrayInputStream(certBytes));
                }

                boolean shouldDecrypt = (targetAlias == null || targetAlias.equals(alias));
                if (shouldDecrypt && keyPass != null && chain.length > 0) {
                    byte[] pkcs8 = decryptJksKeyProtector(protectedKey, keyPass);
                    String alg = chain[0].getPublicKey().getAlgorithm();
                    PrivateKey pk = KeyFactory.getInstance(alg).generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
                    outKs.setKeyEntry(alias, pk, keyPass, chain);
                } else if (chain.length > 0) {
                    outKs.setCertificateEntry(alias, chain[0]);
                }
            } else if (tag == 2) {
                String alias = dis.readUTF();
                dis.readLong();
                if (version == 2) {
                    dis.readUTF();
                }
                int certLen = dis.readInt();
                byte[] certBytes = new byte[certLen];
                dis.readFully(certBytes);
                Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
                outKs.setCertificateEntry(alias, cert);
            } else {
                throw new IOException("Unknown JKS entry tag: " + tag);
            }
        }
        return outKs;
    }

    private static MessageDigest getPreKeyedJksDigest(char[] password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] passwdBytes = charsToUtf16Be(password);
        md.update(passwdBytes);
        Arrays.fill(passwdBytes, (byte) 0);
        md.update("Mighty Aphrodite".getBytes(StandardCharsets.UTF_8));
        return md;
    }

    private static byte[] decryptJksKeyProtector(byte[] encryptedPrivateKeyInfo, char[] password) throws Exception {
        // Unwrap ASN.1 EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
        int pos = 0;
        if ((encryptedPrivateKeyInfo[pos++] & 0xFF) != 0x30) {
            throw new IOException("Invalid JKS EncryptedPrivateKeyInfo wrapper.");
        }
        pos += readDerLengthBytes(encryptedPrivateKeyInfo, pos);
        if ((encryptedPrivateKeyInfo[pos++] & 0xFF) != 0x30) {
            throw new IOException("Invalid JKS AlgorithmIdentifier.");
        }
        int algLen = readDerLengthValue(encryptedPrivateKeyInfo, pos);
        pos += readDerLengthBytes(encryptedPrivateKeyInfo, pos) + algLen;

        if ((encryptedPrivateKeyInfo[pos++] & 0xFF) != 0x04) {
            throw new IOException("Missing encrypted key OCTET STRING.");
        }
        int encrLen = readDerLengthValue(encryptedPrivateKeyInfo, pos);
        pos += readDerLengthBytes(encryptedPrivateKeyInfo, pos);

        if (encrLen < 40 || pos + encrLen > encryptedPrivateKeyInfo.length) {
            throw new IOException("Corrupted JKS key protector payload.");
        }

        byte[] salt = Arrays.copyOfRange(encryptedPrivateKeyInfo, pos, pos + 20);
        int plainLen = encrLen - 40;
        byte[] cipher = Arrays.copyOfRange(encryptedPrivateKeyInfo, pos + 20, pos + 20 + plainLen);
        byte[] expectedMac = Arrays.copyOfRange(encryptedPrivateKeyInfo, pos + 20 + plainLen, pos + encrLen);

        byte[] passwdBytes = charsToUtf16Be(password);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = salt;
            byte[] plain = new byte[plainLen];
            int offset = 0;
            while (offset < plainLen) {
                md.reset();
                md.update(passwdBytes);
                md.update(digest);
                digest = md.digest();
                int take = Math.min(20, plainLen - offset);
                for (int j = 0; j < take; j++) {
                    plain[offset + j] = (byte) (cipher[offset + j] ^ digest[j]);
                }
                offset += take;
            }

            md.reset();
            md.update(passwdBytes);
            md.update(plain);
            byte[] actualMac = md.digest();
            if (!MessageDigest.isEqual(actualMac, expectedMac)) {
                throw new IOException("Cannot recover key (incorrect Key Password)");
            }
            return plain;
        } finally {
            Arrays.fill(passwdBytes, (byte) 0);
        }
    }

    private static int readDerLengthValue(byte[] data, int pos) {
        int b = data[pos] & 0xFF;
        if (b < 0x80) return b;
        int numBytes = b & 0x7F;
        int len = 0;
        for (int i = 1; i <= numBytes; i++) {
            len = (len << 8) | (data[pos + i] & 0xFF);
        }
        return len;
    }

    private static int readDerLengthBytes(byte[] data, int pos) {
        int b = data[pos] & 0xFF;
        return b < 0x80 ? 1 : 1 + (b & 0x7F);
    }

    private static byte[] charsToUtf16Be(char[] chars) {
        byte[] bytes = new byte[chars.length * 2];
        for (int i = 0; i < chars.length; i++) {
            bytes[i * 2] = (byte) (chars[i] >> 8);
            bytes[i * 2 + 1] = (byte) (chars[i] & 0xFF);
        }
        return bytes;
    }

    /**
     * Parses Java KeyStore (JKS) binary structure directly.
     * JKS stores entry aliases in plaintext even though private key blobs are encrypted.
     */
    public static List<String> extractAliasesFromJksBinary(File file) {
        List<String> aliases = new ArrayList<>();
        try (DataInputStream dis = new DataInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            int magic = dis.readInt();
            if (magic != JKS_MAGIC) {
                return aliases;
            }
            int version = dis.readInt();
            if (version != 1 && version != 2) {
                return aliases;
            }
            int count = dis.readInt();
            if (count <= 0 || count > 1000) {
                return aliases;
            }

            for (int i = 0; i < count; i++) {
                int tag = dis.readInt();
                if (tag == 1) {
                    String alias = dis.readUTF();
                    if (!alias.isEmpty()) {
                        aliases.add(alias);
                    }
                    dis.readLong();
                    int keyLen = dis.readInt();
                    if (keyLen < 0 || keyLen > 10_000_000) break;
                    skipFully(dis, keyLen);

                    int chainLen = dis.readInt();
                    if (chainLen < 0 || chainLen > 100) break;
                    for (int c = 0; c < chainLen; c++) {
                        if (version == 2) {
                            dis.readUTF();
                        }
                        int certLen = dis.readInt();
                        if (certLen < 0 || certLen > 10_000_000) break;
                        skipFully(dis, certLen);
                    }
                } else if (tag == 2) {
                    String alias = dis.readUTF();
                    if (!alias.isEmpty()) {
                        aliases.add(alias);
                    }
                    dis.readLong();
                    if (version == 2) {
                        dis.readUTF();
                    }
                    int certLen = dis.readInt();
                    if (certLen < 0 || certLen > 10_000_000) break;
                    skipFully(dis, certLen);
                } else {
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        return aliases;
    }

    private static void skipFully(DataInputStream dis, int n) throws IOException {
        int remaining = n;
        while (remaining > 0) {
            int skipped = dis.skipBytes(remaining);
            if (skipped <= 0) {
                if (dis.read() == -1) {
                    throw new EOFException();
                }
                remaining--;
            } else {
                remaining -= skipped;
            }
        }
    }
}
