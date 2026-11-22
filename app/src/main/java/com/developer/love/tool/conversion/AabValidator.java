package com.developer.love.tool.conversion;

import com.developer.love.tool.core.AppUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Pure Java JAR / AAB v1 cryptographic signature validator.
 * Verifies:
 *  1) Every non-signature ZIP payload entry matches its MANIFEST.MF digest.
 *  2) .SF digest-of-manifest, digest-of-main-attributes, and per-stanza MANIFEST.MF digests.
 *  3) PKCS#7 SignedData signature block (.RSA / .DSA / .EC) cryptographically against .SF bytes
 *     (supporting both bare SignerInfo and [0] authenticatedAttributes with messageDigest).
 */
public class AabValidator {

    public static class ValidationResult {
        public boolean isValid;
        public boolean hasManifest;
        public boolean hasSignatureFile;
        public boolean hasSignatureBlock;
        public String signerSubject;
        public String signerSha256;
        public int verifiedEntriesCount;
        public String statusDescription;
        public String errorMessage;
    }

    private static final class DerElement {
        final int tag;
        final int headerLen;
        final int contentOffset;
        final int contentLen;
        final int totalLen;

        DerElement(int tag, int headerLen, int contentOffset, int contentLen) {
            this.tag = tag;
            this.headerLen = headerLen;
            this.contentOffset = contentOffset;
            this.contentLen = contentLen;
            this.totalLen = headerLen + contentLen;
        }
    }

    private static final class ParsedManifestSections {
        byte[] mainAttrsBytes;
        final Map<String, byte[]> entryStanzas = new HashMap<>();
    }

    public static ValidationResult verifySignedArchive(File archiveFile, X509Certificate expectedCert) {
        ValidationResult result = new ValidationResult();
        if (archiveFile == null || !archiveFile.exists()) {
            result.errorMessage = "Archive file not found.";
            return result;
        }

        try (ZipFile zip = new ZipFile(archiveFile)) {
            ZipEntry manifestEntry = zip.getEntry("META-INF/MANIFEST.MF");
            if (manifestEntry != null) {
                result.hasManifest = true;
            }

            List<String> sfEntries = new ArrayList<>();
            Map<String, String> blockByBase = new HashMap<>();

            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                if (!name.startsWith("META-INF/") || e.isDirectory()) {
                    continue;
                }
                String upper = name.toUpperCase(Locale.US);
                if (upper.endsWith(".SF")) {
                    sfEntries.add(name);
                    result.hasSignatureFile = true;
                } else if (upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC")) {
                    int dot = name.lastIndexOf('.');
                    String base = name.substring(0, dot).toUpperCase(Locale.US);
                    blockByBase.put(base, name);
                    result.hasSignatureBlock = true;
                }
            }

            if (!result.hasManifest || !result.hasSignatureFile || !result.hasSignatureBlock) {
                result.isValid = false;
                result.errorMessage = "Archive is missing required signature metadata (MANIFEST.MF, .SF or .RSA/.DSA/.EC).";
                return result;
            }

            // Pick a matching .SF + signature block pair
            String chosenSf = null;
            String chosenBlock = null;
            for (String sf : sfEntries) {
                int dot = sf.lastIndexOf('.');
                String base = sf.substring(0, dot).toUpperCase(Locale.US);
                String matchingBlock = blockByBase.get(base);
                if (matchingBlock != null) {
                    chosenSf = sf;
                    chosenBlock = matchingBlock;
                    break;
                }
            }

            if (chosenSf == null || chosenBlock == null) {
                result.isValid = false;
                result.errorMessage = "No matching .SF and signature block pair (.RSA/.DSA/.EC) found in META-INF/.";
                return result;
            }

            // 1. Read & verify MANIFEST.MF against all ZIP payload entries
            byte[] manifestBytes = readEntryBytes(zip, manifestEntry);
            Manifest manifest = new Manifest(new ByteArrayInputStream(manifestBytes));
            ParsedManifestSections parsedManifest = parseManifestSections(manifestBytes);

            int verifiedCount = verifyManifestPayloadEntries(zip, manifest, result);

            // 2. Read & verify .SF digests against MANIFEST.MF
            byte[] sfBytes = readEntryBytes(zip, zip.getEntry(chosenSf));
            verifySignatureFileAgainstManifest(sfBytes, manifestBytes, parsedManifest, manifest);

            // 3. Cryptographically verify PKCS#7 signature block (.RSA/.DSA/.EC) over .SF bytes
            byte[] pkcs7Bytes = readEntryBytes(zip, zip.getEntry(chosenBlock));
            X509Certificate verifiedSignerCert = verifyPkcs7Signature(pkcs7Bytes, sfBytes, expectedCert);

            result.verifiedEntriesCount = verifiedCount;
            result.signerSubject = verifiedSignerCert.getSubjectX500Principal().getName();
            result.signerSha256 = AppUtils.getFingerprint(verifiedSignerCert.getEncoded(), "SHA-256");
            result.isValid = true;
            result.statusDescription = "Signature Verified: Cryptographic PKCS#7 signature and all "
                    + verifiedCount + " payload entry digests validated.";

        } catch (Exception e) {
            result.isValid = false;
            result.errorMessage = "Verification failed: " + e.getMessage();
        }

        return result;
    }

    private static int verifyManifestPayloadEntries(
            ZipFile zip,
            Manifest manifest,
            ValidationResult result
    ) throws Exception {
        Set<String> seenPayloadEntries = new HashSet<>();
        int verifiedCount = 0;

        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            if (ze.isDirectory()) continue;
            String name = ze.getName();
            if (isSignatureMetadataEntry(name)) continue;

            seenPayloadEntries.add(name);
            Attributes attrs = manifest.getAttributes(name);
            if (attrs == null) {
                throw new SecurityException("Unsigned payload entry missing from MANIFEST.MF: " + name);
            }
            if (!verifyDigestAttributes(attrs, readZipStream(zip, ze))) {
                throw new SecurityException("Digest mismatch or missing digest attribute for entry: " + name);
            }
            verifiedCount++;
        }

        if (verifiedCount == 0) {
            throw new SecurityException("Archive contains no verifiable payload entries.");
        }

        // Reject manifests listing phantom files deleted/omitted from archive
        for (String manifestEntryName : manifest.getEntries().keySet()) {
            if (!seenPayloadEntries.contains(manifestEntryName)) {
                throw new SecurityException("MANIFEST.MF lists missing archive entry: " + manifestEntryName);
            }
        }

        result.verifiedEntriesCount = verifiedCount;
        return verifiedCount;
    }

    private static void verifySignatureFileAgainstManifest(
            byte[] sfBytes,
            byte[] manifestBytes,
            ParsedManifestSections parsedManifest,
            Manifest manifest
    ) throws Exception {
        Manifest sf = new Manifest(new ByteArrayInputStream(sfBytes));
        Attributes sfMain = sf.getMainAttributes();

        boolean checkedWholeManifest = false;
        String[] wholeHeaders = {
                "SHA-512-Digest-Manifest", "SHA-384-Digest-Manifest",
                "SHA-256-Digest-Manifest", "SHA1-Digest-Manifest", "SHA-1-Digest-Manifest"
        };
        String[] wholeAlgs = {"SHA-512", "SHA-384", "SHA-256", "SHA-1", "SHA-1"};

        for (int i = 0; i < wholeHeaders.length; i++) {
            String expected = sfMain.getValue(wholeHeaders[i]);
            if (expected != null) {
                String actual = digestBase64(wholeAlgs[i], manifestBytes);
                if (!expected.trim().equals(actual.trim())) {
                    throw new SecurityException(".SF " + wholeHeaders[i] + " does not match MANIFEST.MF.");
                }
                checkedWholeManifest = true;
            }
        }

        String[] mainAttrHeaders = {
                "SHA-512-Digest-Manifest-Main-Attributes", "SHA-384-Digest-Manifest-Main-Attributes",
                "SHA-256-Digest-Manifest-Main-Attributes", "SHA1-Digest-Manifest-Main-Attributes", "SHA-1-Digest-Manifest-Main-Attributes"
        };
        for (int i = 0; i < mainAttrHeaders.length; i++) {
            String expected = sfMain.getValue(mainAttrHeaders[i]);
            if (expected != null && parsedManifest.mainAttrsBytes != null) {
                String actual = digestBase64(wholeAlgs[i], parsedManifest.mainAttrsBytes);
                if (!expected.trim().equals(actual.trim())) {
                    throw new SecurityException(".SF " + mainAttrHeaders[i] + " mismatch.");
                }
            }
        }

        boolean verifiedIndividualEntries = false;
        for (Map.Entry<String, Attributes> e : sf.getEntries().entrySet()) {
            String entryName = e.getKey();
            byte[] stanzaBytes = parsedManifest.entryStanzas.get(entryName);
            if (stanzaBytes == null) {
                throw new SecurityException(".SF references entry missing from MANIFEST.MF: " + entryName);
            }
            if (!verifyStanzaDigestAttributes(e.getValue(), stanzaBytes)) {
                throw new SecurityException(".SF stanza digest mismatch for: " + entryName);
            }
            verifiedIndividualEntries = true;
        }

        if (!checkedWholeManifest && !verifiedIndividualEntries) {
            throw new SecurityException(".SF contains no verifiable manifest or stanza digests.");
        }

        if (!checkedWholeManifest) {
            // Ensure every manifest entry was explicitly covered by an .SF stanza
            for (String mEntry : manifest.getEntries().keySet()) {
                if (sf.getAttributes(mEntry) == null) {
                    throw new SecurityException("Entry missing from .SF signature file: " + mEntry);
                }
            }
        }
    }

    private static boolean verifyDigestAttributes(Attributes attrs, byte[] data) throws Exception {
        return checkHeaderDigests(
                attrs,
                data,
                new String[]{"SHA-512-Digest", "SHA-384-Digest", "SHA-256-Digest", "SHA1-Digest", "SHA-1-Digest"},
                new String[]{"SHA-512", "SHA-384", "SHA-256", "SHA-1", "SHA-1"}
        );
    }

    private static boolean verifyStanzaDigestAttributes(Attributes attrs, byte[] stanzaBytes) throws Exception {
        return checkHeaderDigests(
                attrs,
                stanzaBytes,
                new String[]{"SHA-512-Digest", "SHA-384-Digest", "SHA-256-Digest", "SHA1-Digest", "SHA-1-Digest"},
                new String[]{"SHA-512", "SHA-384", "SHA-256", "SHA-1", "SHA-1"}
        );
    }

    private static boolean checkHeaderDigests(
            Attributes attrs,
            byte[] data,
            String[] headerNames,
            String[] algs
    ) throws Exception {
        boolean foundAny = false;
        for (int i = 0; i < headerNames.length; i++) {
            String expected = attrs.getValue(headerNames[i]);
            if (expected != null) {
                foundAny = true;
                String actual = digestBase64(algs[i], data);
                if (!expected.trim().equals(actual.trim())) {
                    return false;
                }
            }
        }
        return foundAny;
    }

    private static String digestBase64(String alg, byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance(alg);
        return AppUtils.toBase64(md.digest(data));
    }

    private static ParsedManifestSections parseManifestSections(byte[] raw) {
        ParsedManifestSections out = new ParsedManifestSections();
        int len = raw.length;
        int pos = 0;
        boolean firstSection = true;

        while (pos < len) {
            int sectionStart = pos;
            int lineStart = pos;
            String currentEntryName = null;
            StringBuilder unwrappedName = null;
            boolean inNameHeader = false;

            while (pos < len) {
                int lineEnd = lineStart;
                while (lineEnd < len && raw[lineEnd] != '\n' && raw[lineEnd] != '\r') {
                    lineEnd++;
                }
                int nextPos = lineEnd;
                if (nextPos < len && raw[nextPos] == '\r') nextPos++;
                if (nextPos < len && raw[nextPos] == '\n') nextPos++;

                if (lineEnd == lineStart) {
                    // Blank line ends current section (keep trailing blank line in byte slice)
                    pos = nextPos;
                    break;
                }

                String line = new String(raw, lineStart, lineEnd - lineStart, StandardCharsets.UTF_8);
                if (inNameHeader) {
                    if (line.startsWith(" ")) {
                        unwrappedName.append(line.substring(1));
                    } else {
                        currentEntryName = unwrappedName.toString();
                        inNameHeader = false;
                    }
                }
                if (!inNameHeader && line.startsWith("Name: ")) {
                    unwrappedName = new StringBuilder(line.substring(6));
                    inNameHeader = true;
                }

                lineStart = nextPos;
                pos = nextPos;
            }

            if (inNameHeader && unwrappedName != null) {
                currentEntryName = unwrappedName.toString();
            }

            byte[] sectionBytes = Arrays.copyOfRange(raw, sectionStart, pos);
            if (firstSection) {
                out.mainAttrsBytes = sectionBytes;
                firstSection = false;
            } else if (currentEntryName != null && !currentEntryName.isEmpty()) {
                out.entryStanzas.put(currentEntryName, sectionBytes);
            }
        }
        return out;
    }

    private static X509Certificate verifyPkcs7Signature(
            byte[] der,
            byte[] sfBytes,
            X509Certificate expectedCert
    ) throws Exception {
        DerElement contentInfo = readDer(der, 0, der.length);
        if (contentInfo.tag != 0x30) {
            throw new SecurityException("Invalid PKCS#7 ContentInfo DER.");
        }

        int ciPos = contentInfo.contentOffset;
        int ciEnd = ciPos + contentInfo.contentLen;
        DerElement contentType = readDer(der, ciPos, ciEnd);
        String ctOid = decodeOid(der, contentType.contentOffset, contentType.contentLen);
        if (!"1.2.840.113549.1.7.2".equals(ctOid)) {
            throw new SecurityException("PKCS#7 block is not SignedData (OID=" + ctOid + ").");
        }
        ciPos += contentType.totalLen;

        DerElement explicitContent = readDer(der, ciPos, ciEnd);
        if (explicitContent.tag != 0xA0) {
            throw new SecurityException("Missing [0] EXPLICIT SignedData wrapper.");
        }

        DerElement signedData = readDer(der, explicitContent.contentOffset,
                explicitContent.contentOffset + explicitContent.contentLen);
        if (signedData.tag != 0x30) {
            throw new SecurityException("Invalid PKCS#7 SignedData sequence.");
        }

        int sdPos = signedData.contentOffset;
        int sdEnd = sdPos + signedData.contentLen;

        // version
        DerElement versionEl = readDer(der, sdPos, sdEnd);
        sdPos += versionEl.totalLen;

        // digestAlgorithms SET
        DerElement digestAlgsEl = readDer(der, sdPos, sdEnd);
        sdPos += digestAlgsEl.totalLen;

        // encapContentInfo SEQUENCE
        DerElement encapEl = readDer(der, sdPos, sdEnd);
        sdPos += encapEl.totalLen;

        // Optional [0] IMPLICIT certificates and [1] IMPLICIT crls
        List<X509Certificate> embeddedCerts = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while (sdPos < sdEnd) {
            DerElement next = readDer(der, sdPos, sdEnd);
            if (next.tag == 0xA0) {
                int cPos = next.contentOffset;
                int cEnd = cPos + next.contentLen;
                while (cPos < cEnd) {
                    DerElement certEl = readDer(der, cPos, cEnd);
                    byte[] certBytes = Arrays.copyOfRange(der, cPos, cPos + certEl.totalLen);
                    Certificate c = cf.generateCertificate(new ByteArrayInputStream(certBytes));
                    if (c instanceof X509Certificate) {
                        embeddedCerts.add((X509Certificate) c);
                    }
                    cPos += certEl.totalLen;
                }
                sdPos += next.totalLen;
            } else if (next.tag == 0xA1) {
                sdPos += next.totalLen;
            } else {
                break;
            }
        }

        if (embeddedCerts.isEmpty()) {
            throw new SecurityException("PKCS#7 signature block contains no embedded X.509 certificate.");
        }

        // signerInfos SET
        DerElement signerInfosSet = readDer(der, sdPos, sdEnd);
        if (signerInfosSet.tag != 0x31) {
            throw new SecurityException("Missing SignerInfos SET in PKCS#7 SignedData.");
        }

        int siPos = signerInfosSet.contentOffset;
        int siEnd = siPos + signerInfosSet.contentLen;
        if (siPos >= siEnd) {
            throw new SecurityException("Empty SignerInfos SET in PKCS#7 SignedData.");
        }

        Exception lastVerifyError = null;
        while (siPos < siEnd) {
            DerElement signerInfoEl = readDer(der, siPos, siEnd);
            siPos += signerInfoEl.totalLen;

            try {
                X509Certificate matchedCert = verifySingleSignerInfo(
                        der,
                        signerInfoEl.contentOffset,
                        signerInfoEl.contentOffset + signerInfoEl.contentLen,
                        embeddedCerts,
                        sfBytes
                );
                if (expectedCert != null && !Arrays.equals(matchedCert.getEncoded(), expectedCert.getEncoded())) {
                    throw new SecurityException("Archive certificate does not match expected keystore certificate.");
                }
                return matchedCert;
            } catch (Exception e) {
                lastVerifyError = e;
            }
        }

        throw lastVerifyError != null ? lastVerifyError : new SecurityException("Signature verification failed.");
    }

    private static X509Certificate verifySingleSignerInfo(
            byte[] der,
            int p,
            int end,
            List<X509Certificate> embeddedCerts,
            byte[] sfBytes
    ) throws Exception {
        // 1. version INTEGER
        DerElement ver = readDer(der, p, end);
        p += ver.totalLen;

        // 2. sid (IssuerAndSerialNumber SEQUENCE or [0] SubjectKeyIdentifier)
        DerElement sid = readDer(der, p, end);
        byte[] issuerBytes = null;
        BigInteger serialNumber = null;
        if (sid.tag == 0x30) {
            int iasPos = sid.contentOffset;
            int iasEnd = iasPos + sid.contentLen;
            DerElement issuerEl = readDer(der, iasPos, iasEnd);
            issuerBytes = Arrays.copyOfRange(der, iasPos, iasPos + issuerEl.totalLen);
            iasPos += issuerEl.totalLen;
            DerElement serialEl = readDer(der, iasPos, iasEnd);
            serialNumber = new BigInteger(Arrays.copyOfRange(der, serialEl.contentOffset,
                    serialEl.contentOffset + serialEl.contentLen));
        }
        p += sid.totalLen;

        // 3. digestAlgorithm AlgorithmIdentifier
        DerElement digAlgEl = readDer(der, p, end);
        String digOid = parseAlgOid(der, digAlgEl);
        String jcaDigestAlg = mapDigestOidToName(digOid);
        p += digAlgEl.totalLen;

        // 4. Optional authenticatedAttributes [0] IMPLICIT Attributes
        byte[] signedAttrsSetBytes = null;
        byte[] messageDigestAttrVal = null;
        DerElement maybeAttrs = readDer(der, p, end);
        if (maybeAttrs.tag == 0xA0) {
            // Re-tag 0xA0 -> 0x31 (SET OF) per RFC 5652 for signature verification
            signedAttrsSetBytes = Arrays.copyOfRange(der, p, p + maybeAttrs.totalLen);
            signedAttrsSetBytes[0] = 0x31;
            messageDigestAttrVal = extractMessageDigestAttr(der, maybeAttrs.contentOffset,
                    maybeAttrs.contentOffset + maybeAttrs.contentLen);
            p += maybeAttrs.totalLen;
        }

        // 5. signatureAlgorithm AlgorithmIdentifier
        DerElement sigAlgEl = readDer(der, p, end);
        String sigAlgOid = parseAlgOid(der, sigAlgEl);
        String jcaSigAlg = mapSigAlgOid(sigAlgOid, jcaDigestAlg);
        p += sigAlgEl.totalLen;

        // 6. signature OCTET STRING
        DerElement sigBytesEl = readDer(der, p, end);
        if (sigBytesEl.tag != 0x04) {
            throw new SecurityException("Missing signature OCTET STRING in SignerInfo.");
        }
        byte[] rawSigBytes = Arrays.copyOfRange(der, sigBytesEl.contentOffset,
                sigBytesEl.contentOffset + sigBytesEl.contentLen);

        // If authenticatedAttributes present, messageDigest must equal digest(sfBytes)
        byte[] dataToVerify = sfBytes;
        if (signedAttrsSetBytes != null) {
            if (messageDigestAttrVal == null) {
                throw new SecurityException("SignedAttributes missing required messageDigest attribute.");
            }
            byte[] actualSfDigest = MessageDigest.getInstance(jcaDigestAlg).digest(sfBytes);
            if (!MessageDigest.isEqual(actualSfDigest, messageDigestAttrVal)) {
                throw new SecurityException(".SF file digest does not match PKCS#7 messageDigest.");
            }
            dataToVerify = signedAttrsSetBytes;
        }

        // Locate matching signer certificate
        List<X509Certificate> candidates = new ArrayList<>();
        if (issuerBytes != null && serialNumber != null) {
            for (X509Certificate cert : embeddedCerts) {
                if (serialNumber.equals(cert.getSerialNumber())
                        && Arrays.equals(issuerBytes, cert.getIssuerX500Principal().getEncoded())) {
                    candidates.add(cert);
                }
            }
            // Fallback for minor DN encoding variations (e.g., UTF8String vs PrintableString): match serial
            if (candidates.isEmpty()) {
                for (X509Certificate cert : embeddedCerts) {
                    if (serialNumber.equals(cert.getSerialNumber())) {
                        candidates.add(cert);
                    }
                }
            }
        }
        if (candidates.isEmpty()) {
            candidates.addAll(embeddedCerts);
        }

        for (X509Certificate cert : candidates) {
            Signature sig = Signature.getInstance(jcaSigAlg);
            sig.initVerify(cert.getPublicKey());
            sig.update(dataToVerify);
            if (sig.verify(rawSigBytes)) {
                return cert;
            }
        }

        throw new SecurityException("Cryptographic signature verification against .SF failed (" + jcaSigAlg + ").");
    }

    private static byte[] extractMessageDigestAttr(byte[] der, int pos, int end) throws SecurityException {
        while (pos < end) {
            DerElement attrSeq = readDer(der, pos, end);
            pos += attrSeq.totalLen;
            if (attrSeq.tag != 0x30) continue;

            int aPos = attrSeq.contentOffset;
            int aEnd = aPos + attrSeq.contentLen;
            DerElement oidEl = readDer(der, aPos, aEnd);
            String oid = decodeOid(der, oidEl.contentOffset, oidEl.contentLen);
            aPos += oidEl.totalLen;

            if ("1.2.840.113549.1.9.4".equals(oid) && aPos < aEnd) {
                DerElement valSet = readDer(der, aPos, aEnd);
                if (valSet.tag == 0x31 && valSet.contentLen > 0) {
                    DerElement valOctet = readDer(der, valSet.contentOffset, valSet.contentOffset + valSet.contentLen);
                    if (valOctet.tag == 0x04) {
                        return Arrays.copyOfRange(der, valOctet.contentOffset,
                                valOctet.contentOffset + valOctet.contentLen);
                    }
                }
            }
        }
        return null;
    }

    private static String parseAlgOid(byte[] der, DerElement algSeq) throws SecurityException {
        if (algSeq.tag != 0x30) {
            throw new SecurityException("Invalid AlgorithmIdentifier DER sequence.");
        }
        DerElement oidEl = readDer(der, algSeq.contentOffset, algSeq.contentOffset + algSeq.contentLen);
        if (oidEl.tag != 0x06) {
            throw new SecurityException("Expected OID inside AlgorithmIdentifier.");
        }
        return decodeOid(der, oidEl.contentOffset, oidEl.contentLen);
    }

    private static String mapDigestOidToName(String oid) throws SecurityException {
        switch (oid) {
            case "1.3.14.3.2.26":
                return "SHA-1";
            case "2.16.840.1.101.3.4.2.1":
                return "SHA-256";
            case "2.16.840.1.101.3.4.2.2":
                return "SHA-384";
            case "2.16.840.1.101.3.4.2.3":
                return "SHA-512";
            default:
                throw new SecurityException("Unsupported digest OID: " + oid);
        }
    }

    private static String mapSigAlgOid(String oid, String digestAlg) throws SecurityException {
        String digestPrefix = digestAlg.replace("-", ""); // e.g., SHA256, SHA1, SHA512
        switch (oid) {
            case "1.2.840.113549.1.1.1": // rsaEncryption
                return digestPrefix + "withRSA";
            case "1.2.840.113549.1.1.5":
                return "SHA1withRSA";
            case "1.2.840.113549.1.1.11":
                return "SHA256withRSA";
            case "1.2.840.113549.1.1.12":
                return "SHA384withRSA";
            case "1.2.840.113549.1.1.13":
                return "SHA512withRSA";
            case "1.2.840.10045.2.1": // id-ecPublicKey (used by some signers)
                return digestPrefix + "withECDSA";
            case "1.2.840.10045.4.1":
                return "SHA1withECDSA";
            case "1.2.840.10045.4.3.2":
                return "SHA256withECDSA";
            case "1.2.840.10045.4.3.3":
                return "SHA384withECDSA";
            case "1.2.840.10045.4.3.4":
                return "SHA512withECDSA";
            case "1.2.840.10040.4.1": // id-dsa
                return digestPrefix + "withDSA";
            case "1.2.840.10040.4.3":
                return "SHA1withDSA";
            case "2.16.840.1.101.3.4.3.1":
                return "SHA224withDSA";
            case "2.16.840.1.101.3.4.3.2":
                return "SHA256withDSA";
            default:
                throw new SecurityException("Unsupported signature algorithm OID: " + oid);
        }
    }

    private static DerElement readDer(byte[] der, int pos, int limit) throws SecurityException {
        if (pos + 2 > limit || pos < 0) {
            throw new SecurityException("Truncated DER structure at offset " + pos);
        }
        int tag = der[pos] & 0xFF;
        int lenByte = der[pos + 1] & 0xFF;
        int headerLen;
        int contentLen;
        if ((lenByte & 0x80) == 0) {
            headerLen = 2;
            contentLen = lenByte;
        } else {
            int numOctets = lenByte & 0x7F;
            if (numOctets == 0 || numOctets > 4 || pos + 2 + numOctets > limit) {
                throw new SecurityException("Unsupported or truncated DER length at offset " + pos);
            }
            headerLen = 2 + numOctets;
            contentLen = 0;
            for (int i = 0; i < numOctets; i++) {
                contentLen = (contentLen << 8) | (der[pos + 2 + i] & 0xFF);
            }
        }
        int contentOffset = pos + headerLen;
        if (contentLen < 0 || contentOffset + contentLen > limit) {
            throw new SecurityException("DER element exceeds buffer bounds at offset " + pos);
        }
        return new DerElement(tag, headerLen, contentOffset, contentLen);
    }

    private static String decodeOid(byte[] der, int offset, int len) throws SecurityException {
        if (len <= 0 || offset + len > der.length) {
            throw new SecurityException("Invalid empty OID.");
        }
        StringBuilder sb = new StringBuilder();
        int first = der[offset] & 0xFF;
        sb.append(first / 40).append('.').append(first % 40);
        long value = 0;
        for (int i = 1; i < len; i++) {
            int b = der[offset + i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                sb.append('.').append(value);
                value = 0;
            }
        }
        return sb.toString();
    }

    private static boolean isSignatureMetadataEntry(String name) {
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

    private static byte[] readEntryBytes(ZipFile zip, ZipEntry entry) throws Exception {
        if (entry == null) {
            throw new SecurityException("Missing required archive entry.");
        }
        return readZipStream(zip, entry);
    }

    private static byte[] readZipStream(ZipFile zip, ZipEntry entry) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        try (InputStream is = zip.getInputStream(entry)) {
            int r;
            while ((r = is.read(buf)) != -1) {
                baos.write(buf, 0, r);
            }
        }
        return baos.toByteArray();
    }
}
