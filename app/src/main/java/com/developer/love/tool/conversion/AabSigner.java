package com.developer.love.tool.conversion;

import com.developer.love.tool.core.AppUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class AabSigner {

    public static class SigningResult {
        public boolean isSuccess;
        public File signedFile;
        public String alias;
        public String certificateSha256;
        public String signatureAlgorithm;
        public int entriesSigned;
        public String errorMessage;
    }

    public static SigningResult signArchive(
            File unsignedArchive,
            File outputDir,
            String outputName,
            KeyStore keyStore,
            String alias,
            String keyPassword
    ) {
        SigningResult result = new SigningResult();
        if (unsignedArchive == null || !unsignedArchive.exists()) {
            result.errorMessage = "Input archive does not exist.";
            return result;
        }

        File signedFile = null;
        char[] pass = keyPassword != null ? keyPassword.toCharArray() : new char[0];
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, pass);
            if (privateKey == null) {
                result.errorMessage = "Private key for alias '" + alias + "' could not be retrieved from keystore.";
                return result;
            }

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            if (cert == null) {
                result.errorMessage = "Certificate for alias '" + alias + "' not found.";
                return result;
            }

            String keyAlg = privateKey.getAlgorithm() != null
                    ? privateKey.getAlgorithm().toUpperCase(Locale.US)
                    : "RSA";
            final String jcaSigAlg;
            final String blockExt;
            final byte[] sigAlgOid;
            final boolean includeNullParam;

            if ("RSA".equals(keyAlg)) {
                jcaSigAlg = "SHA256withRSA";
                blockExt = ".RSA";
                // 1.2.840.113549.1.1.1 (rsaEncryption)
                sigAlgOid = new byte[]{0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01};
                includeNullParam = true;
            } else if ("EC".equals(keyAlg) || "ECDSA".equals(keyAlg)) {
                jcaSigAlg = "SHA256withECDSA";
                blockExt = ".EC";
                // 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
                sigAlgOid = new byte[]{0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02};
                includeNullParam = false;
            } else if ("DSA".equals(keyAlg)) {
                jcaSigAlg = "SHA256withDSA";
                blockExt = ".DSA";
                // 2.16.840.1.101.3.4.3.2 (dsa_with_SHA256)
                sigAlgOid = new byte[]{0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02};
                includeNullParam = false;
            } else {
                result.errorMessage = "Unsupported signing key algorithm: " + keyAlg + " (supported: RSA, EC, DSA).";
                return result;
            }

            String cleanAlias = alias.replaceAll("[^a-zA-Z0-9_-]", "_").toUpperCase(Locale.US);
            if (cleanAlias.length() > 8) {
                cleanAlias = cleanAlias.substring(0, 8);
            }
            if (cleanAlias.isEmpty()) {
                cleanAlias = "CERT";
            }

            if (outputDir != null && !outputDir.exists()) {
                outputDir.mkdirs();
            }
            signedFile = new File(outputDir, outputName);

            // 1. Calculate SHA-256 digests for all entries
            Map<String, String> fileDigests = new LinkedHashMap<>();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            try (ZipFile zipIn = new ZipFile(unsignedArchive)) {
                Enumeration<? extends ZipEntry> entries = zipIn.entries();
                byte[] buf = new byte[16384];

                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName();
                    if (entry.isDirectory() || isSignatureFile(name)) {
                        continue;
                    }

                    sha256.reset();
                    try (InputStream is = zipIn.getInputStream(entry)) {
                        int read;
                        while ((read = is.read(buf)) != -1) {
                            sha256.update(buf, 0, read);
                        }
                    }
                    fileDigests.put(name, AppUtils.toBase64(sha256.digest()));
                }
            }

            // 2. Build MANIFEST.MF with standard 72-byte JAR line wrapping and compute per-stanza .SF digests
            ByteArrayOutputStream manifestBaos = new ByteArrayOutputStream();
            ByteArrayOutputStream mainAttrsBaos = new ByteArrayOutputStream();
            writeWrappedManifestLine(mainAttrsBaos, "Manifest-Version: 1.0");
            writeWrappedManifestLine(mainAttrsBaos, "Created-By: DevLoveTool AAB/JAR Signer");
            mainAttrsBaos.write("\r\n".getBytes(StandardCharsets.UTF_8));
            byte[] mainAttrsBytes = mainAttrsBaos.toByteArray();
            manifestBaos.write(mainAttrsBytes);

            Map<String, String> sfEntryDigests = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : fileDigests.entrySet()) {
                ByteArrayOutputStream stanzaBaos = new ByteArrayOutputStream();
                writeWrappedManifestLine(stanzaBaos, "Name: " + e.getKey());
                writeWrappedManifestLine(stanzaBaos, "SHA-256-Digest: " + e.getValue());
                stanzaBaos.write("\r\n".getBytes(StandardCharsets.UTF_8));
                byte[] stanzaBytes = stanzaBaos.toByteArray();
                manifestBaos.write(stanzaBytes);

                // In standard JAR signing, .SF SHA-256-Digest MUST be the digest of the MANIFEST.MF stanza!
                sha256.reset();
                sfEntryDigests.put(e.getKey(), AppUtils.toBase64(sha256.digest(stanzaBytes)));
            }
            byte[] manifestBytes = manifestBaos.toByteArray();

            // 3. Create Signature File (.SF)
            sha256.reset();
            String manifestDigestB64 = AppUtils.toBase64(sha256.digest(manifestBytes));
            sha256.reset();
            String mainAttrsDigestB64 = AppUtils.toBase64(sha256.digest(mainAttrsBytes));

            ByteArrayOutputStream sfBaos = new ByteArrayOutputStream();
            writeWrappedManifestLine(sfBaos, "Signature-Version: 1.0");
            writeWrappedManifestLine(sfBaos, "Created-By: DevLoveTool AAB/JAR Signer");
            writeWrappedManifestLine(sfBaos, "SHA-256-Digest-Manifest: " + manifestDigestB64);
            writeWrappedManifestLine(sfBaos, "SHA-256-Digest-Manifest-Main-Attributes: " + mainAttrsDigestB64);
            sfBaos.write("\r\n".getBytes(StandardCharsets.UTF_8));

            for (Map.Entry<String, String> e : sfEntryDigests.entrySet()) {
                writeWrappedManifestLine(sfBaos, "Name: " + e.getKey());
                writeWrappedManifestLine(sfBaos, "SHA-256-Digest: " + e.getValue());
                sfBaos.write("\r\n".getBytes(StandardCharsets.UTF_8));
            }
            byte[] sfBytes = sfBaos.toByteArray();

            // 4. Cryptographically sign .SF bytes
            Signature signature = Signature.getInstance(jcaSigAlg);
            signature.initSign(privateKey);
            signature.update(sfBytes);
            byte[] rawSigBytes = signature.sign();

            // 5. Build PKCS#7 block for .RSA / .EC / .DSA
            byte[] pkcs7Bytes = buildPkcs7Block(cert, rawSigBytes, sigAlgOid, includeNullParam);

            // 6. Write signed archive
            int entriesCount = 0;
            try (ZipFile zipIn = new ZipFile(unsignedArchive);
                 ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(signedFile))) {

                ZipEntry mEntry = new ZipEntry("META-INF/MANIFEST.MF");
                zipOut.putNextEntry(mEntry);
                zipOut.write(manifestBytes);
                zipOut.closeEntry();

                ZipEntry sfEntry = new ZipEntry("META-INF/" + cleanAlias + ".SF");
                zipOut.putNextEntry(sfEntry);
                zipOut.write(sfBytes);
                zipOut.closeEntry();

                ZipEntry sigBlockEntry = new ZipEntry("META-INF/" + cleanAlias + blockExt);
                zipOut.putNextEntry(sigBlockEntry);
                zipOut.write(pkcs7Bytes);
                zipOut.closeEntry();

                Enumeration<? extends ZipEntry> srcEntries = zipIn.entries();
                byte[] buffer = new byte[16384];

                while (srcEntries.hasMoreElements()) {
                    ZipEntry src = srcEntries.nextElement();
                    if (src.isDirectory() || isSignatureFile(src.getName())) continue;

                    ZipEntry dst = new ZipEntry(src.getName());
                    if (src.getTime() > 0) dst.setTime(src.getTime());
                    zipOut.putNextEntry(dst);

                    try (InputStream is = zipIn.getInputStream(src)) {
                        int read;
                        while ((read = is.read(buffer)) != -1) {
                            zipOut.write(buffer, 0, read);
                        }
                    }
                    zipOut.closeEntry();
                    entriesCount++;
                }

                zipOut.flush();
            }

            result.isSuccess = true;
            result.signedFile = signedFile;
            result.alias = alias;
            result.certificateSha256 = AppUtils.getFingerprint(cert.getEncoded(), "SHA-256");
            result.signatureAlgorithm = jcaSigAlg + " (JAR/AAB v1)";
            result.entriesSigned = entriesCount;

        } catch (Exception e) {
            if (signedFile != null && signedFile.exists()) {
                signedFile.delete();
            }
            result.isSuccess = false;
            result.errorMessage = "Signing error: " + e.getMessage();
        } finally {
            java.util.Arrays.fill(pass, '0');
        }

        return result;
    }

    private static boolean isSignatureFile(String name) {
        if (!name.startsWith("META-INF/")) return false;
        String upper = name.toUpperCase(Locale.US);
        return "META-INF/MANIFEST.MF".equals(upper)
                || upper.endsWith(".SF")
                || upper.endsWith(".RSA")
                || upper.endsWith(".DSA")
                || upper.endsWith(".EC")
                || upper.startsWith("META-INF/CERT.")
                || upper.startsWith("META-INF/SIG-");
    }

    private static void writeWrappedManifestLine(ByteArrayOutputStream out, String line) throws IOException {
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= 70) {
            out.write(bytes);
            out.write("\r\n".getBytes(StandardCharsets.UTF_8));
            return;
        }
        int offset = 0;
        int firstLen = 70;
        out.write(bytes, offset, firstLen);
        out.write("\r\n".getBytes(StandardCharsets.UTF_8));
        offset += firstLen;

        while (offset < bytes.length) {
            out.write(' ');
            int chunk = Math.min(69, bytes.length - offset);
            out.write(bytes, offset, chunk);
            out.write("\r\n".getBytes(StandardCharsets.UTF_8));
            offset += chunk;
        }
    }

    private static byte[] buildPkcs7Block(
            X509Certificate cert,
            byte[] signatureBytes,
            byte[] sigAlgOid,
            boolean includeNullParam
    ) throws Exception {
        byte[] signedDataOid = new byte[]{0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x07, 0x02};
        byte[] dataOid = new byte[]{0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x07, 0x01};

        byte[] sha256Oid = new byte[]{0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
        byte[] nullParam = new byte[]{0x05, 0x00};
        ByteArrayOutputStream sha256Alg = new ByteArrayOutputStream();
        sha256Alg.write(sha256Oid);
        sha256Alg.write(nullParam);
        byte[] digestAlgSeq = encodeSequence(sha256Alg.toByteArray());
        byte[] digestAlgorithmsSet = encodeSet(digestAlgSeq);

        ByteArrayOutputStream contentInfoBaos = new ByteArrayOutputStream();
        contentInfoBaos.write(dataOid);
        byte[] encapContentInfo = encodeSequence(contentInfoBaos.toByteArray());

        byte[] certBytes = cert.getEncoded();
        byte[] certificatesTagged = encodeImplicit(0, certBytes);

        ByteArrayOutputStream sigAlgBaos = new ByteArrayOutputStream();
        sigAlgBaos.write(sigAlgOid);
        if (includeNullParam) {
            sigAlgBaos.write(nullParam);
        }
        byte[] sigAlgSeq = encodeSequence(sigAlgBaos.toByteArray());

        ByteArrayOutputStream iasBaos = new ByteArrayOutputStream();
        iasBaos.write(cert.getIssuerX500Principal().getEncoded());
        iasBaos.write(encodeInteger(cert.getSerialNumber()));
        byte[] issuerAndSerial = encodeSequence(iasBaos.toByteArray());

        ByteArrayOutputStream signerInfoBaos = new ByteArrayOutputStream();
        signerInfoBaos.write(encodeInteger(BigInteger.ONE));
        signerInfoBaos.write(issuerAndSerial);
        signerInfoBaos.write(digestAlgSeq);
        signerInfoBaos.write(sigAlgSeq);
        signerInfoBaos.write(encodeOctetString(signatureBytes));

        byte[] signerInfoSeq = encodeSequence(signerInfoBaos.toByteArray());
        byte[] signerInfosSet = encodeSet(signerInfoSeq);

        ByteArrayOutputStream signedDataBaos = new ByteArrayOutputStream();
        signedDataBaos.write(encodeInteger(BigInteger.ONE));
        signedDataBaos.write(digestAlgorithmsSet);
        signedDataBaos.write(encapContentInfo);
        signedDataBaos.write(certificatesTagged);
        signedDataBaos.write(signerInfosSet);

        byte[] signedDataSeq = encodeSequence(signedDataBaos.toByteArray());

        ByteArrayOutputStream finalBaos = new ByteArrayOutputStream();
        finalBaos.write(signedDataOid);
        finalBaos.write(encodeExplicit(0, signedDataSeq));

        return encodeSequence(finalBaos.toByteArray());
    }

    private static byte[] encodeSequence(byte[] c) throws IOException { return encodeTlv(0x30, c); }
    private static byte[] encodeSet(byte[] c) throws IOException { return encodeTlv(0x31, c); }
    private static byte[] encodeOctetString(byte[] c) throws IOException { return encodeTlv(0x04, c); }
    private static byte[] encodeExplicit(int tag, byte[] c) throws IOException { return encodeTlv(0xA0 | (tag & 0x1F), c); }
    private static byte[] encodeImplicit(int tag, byte[] c) throws IOException { return encodeTlv(0xA0 | (tag & 0x1F), c); }
    private static byte[] encodeInteger(BigInteger v) throws IOException { return encodeTlv(0x02, v.toByteArray()); }

    private static byte[] encodeTlv(int tag, byte[] value) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int length = value != null ? value.length : 0;
        if (length < 128) {
            out.write(length);
        } else if (length < 256) {
            out.write(0x81);
            out.write(length);
        } else if (length < 65536) {
            out.write(0x82);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        } else {
            out.write(0x83);
            out.write((length >> 16) & 0xFF);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
        if (value != null && value.length > 0) {
            out.write(value);
        }
        return out.toByteArray();
    }
}
