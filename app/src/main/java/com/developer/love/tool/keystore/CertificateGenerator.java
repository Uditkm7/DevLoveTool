package com.developer.love.tool.keystore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

public final class CertificateGenerator {
    private CertificateGenerator() {}

    public static class CertParams {
        public String commonName;
        public String organization;
        public String organizationalUnit;
        public String locality;
        public String state;
        public String countryCode;
        public int validityYears = 100;
        public int validityDays = 0; // Optional legacy fallback if validityYears <= 0
    }

    public static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, CertParams params) throws Exception {
        TimeZone utc = TimeZone.getTimeZone("UTC");
        Calendar calBefore = Calendar.getInstance(utc, Locale.US);
        calBefore.add(Calendar.DAY_OF_YEAR, -1); // 1 day before to allow slight clock skew
        Date notBefore = calBefore.getTime();

        Calendar calAfter = Calendar.getInstance(utc, Locale.US);
        if (params.validityYears > 0) {
            calAfter.add(Calendar.YEAR, params.validityYears);
        } else if (params.validityDays > 0) {
            calAfter.add(Calendar.DAY_OF_YEAR, params.validityDays);
        } else {
            calAfter.add(Calendar.YEAR, 100);
        }
        Date notAfter = calAfter.getTime();

        // Positive 64-bit random serial number
        BigInteger serial = new BigInteger(64, new SecureRandom()).abs();
        if (serial.equals(BigInteger.ZERO)) {
            serial = BigInteger.ONE;
        }

        // Build Name (RDN sequence)
        byte[] nameBytes = buildNameSequence(params);

        // Build Validity sequence (RFC 5280: UTCTime < 2050, GeneralizedTime >= 2050)
        byte[] validityBytes = buildValiditySequence(notBefore, notAfter);

        // SubjectPublicKeyInfo is already DER-encoded in kp.getPublic().getEncoded()
        byte[] spkiBytes = keyPair.getPublic().getEncoded();

        // AlgorithmIdentifier for sha256WithRSA: 1.2.840.113549.1.1.11
        byte[] algId = buildSha256WithRsaAlgId();

        // TBSCertificate SEQUENCE
        ByteArrayOutputStream tbsBody = new ByteArrayOutputStream();

        // Version: [0] EXPLICIT INTEGER 2 (v3)
        byte[] v3Int = encodeInteger(BigInteger.valueOf(2));
        tbsBody.write(encodeExplicit(0, v3Int));

        // Serial number
        tbsBody.write(encodeInteger(serial));

        // Signature algorithm
        tbsBody.write(algId);

        // Issuer
        tbsBody.write(nameBytes);

        // Validity
        tbsBody.write(validityBytes);

        // Subject (same as issuer for self-signed)
        tbsBody.write(nameBytes);

        // SubjectPublicKeyInfo
        tbsBody.write(spkiBytes);

        byte[] tbsCertificate = encodeSequence(tbsBody.toByteArray());

        // Sign TBS with private key using SHA256withRSA
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(tbsCertificate);
        byte[] signatureBytes = sig.sign();

        // Assemble Certificate: SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING signature }
        ByteArrayOutputStream certBody = new ByteArrayOutputStream();
        certBody.write(tbsCertificate);
        certBody.write(algId);
        certBody.write(encodeBitString(signatureBytes));

        byte[] completeCertDer = encodeSequence(certBody.toByteArray());

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(completeCertDer));
    }

    private static byte[] buildSha256WithRsaAlgId() throws IOException {
        // OID: 1.2.840.113549.1.1.11 = 2A 86 48 86 F7 0D 01 01 0B
        byte[] oid = new byte[]{0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0B};
        byte[] nullParams = new byte[]{0x05, 0x00};
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(oid);
        out.write(nullParams);
        return encodeSequence(out.toByteArray());
    }

    private static byte[] buildNameSequence(CertParams params) throws IOException {
        ByteArrayOutputStream nameBody = new ByteArrayOutputStream();

        // Country Code (2.5.4.6)
        if (params.countryCode != null && !params.countryCode.trim().isEmpty()) {
            byte[] oid = new byte[]{0x06, 0x03, 0x55, 0x04, 0x06};
            nameBody.write(buildRdn(oid, encodePrintableString(params.countryCode.trim())));
        }

        // State / Province (2.5.4.8)
        if (params.state != null && !params.state.trim().isEmpty()) {
            byte[] oid = new byte[]{0x06, 0x03, 0x55, 0x04, 0x08};
            nameBody.write(buildRdn(oid, encodeUtf8String(params.state.trim())));
        }

        // Locality / City (2.5.4.7)
        if (params.locality != null && !params.locality.trim().isEmpty()) {
            byte[] oid = new byte[]{0x06, 0x03, 0x55, 0x04, 0x07};
            nameBody.write(buildRdn(oid, encodeUtf8String(params.locality.trim())));
        }

        // Organization (2.5.4.10)
        if (params.organization != null && !params.organization.trim().isEmpty()) {
            byte[] oid = new byte[]{0x06, 0x03, 0x55, 0x04, 0x0A};
            nameBody.write(buildRdn(oid, encodeUtf8String(params.organization.trim())));
        }

        // Organizational Unit (2.5.4.11)
        if (params.organizationalUnit != null && !params.organizationalUnit.trim().isEmpty()) {
            byte[] oid = new byte[]{0x06, 0x03, 0x55, 0x04, 0x0B};
            nameBody.write(buildRdn(oid, encodeUtf8String(params.organizationalUnit.trim())));
        }

        // Common Name (2.5.4.3)
        if (params.commonName != null && !params.commonName.trim().isEmpty()) {
            byte[] oid = new byte[]{0x06, 0x03, 0x55, 0x04, 0x03};
            nameBody.write(buildRdn(oid, encodeUtf8String(params.commonName.trim())));
        }

        return encodeSequence(nameBody.toByteArray());
    }

    private static byte[] buildRdn(byte[] oid, byte[] value) throws IOException {
        ByteArrayOutputStream attr = new ByteArrayOutputStream();
        attr.write(oid);
        attr.write(value);
        byte[] attrSeq = encodeSequence(attr.toByteArray());
        return encodeSet(attrSeq);
    }

    private static byte[] buildValiditySequence(Date notBefore, Date notAfter) throws IOException {
        byte[] nbBytes = encodeX509Time(notBefore);
        byte[] naBytes = encodeX509Time(notAfter);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(nbBytes);
        out.write(naBytes);
        return encodeSequence(out.toByteArray());
    }

    private static byte[] encodeX509Time(Date date) throws IOException {
        TimeZone utc = TimeZone.getTimeZone("UTC");
        Calendar cal = Calendar.getInstance(utc, Locale.US);
        cal.setTime(date);
        int year = cal.get(Calendar.YEAR);
        if (year >= 2050) {
            SimpleDateFormat genFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.US);
            genFormat.setTimeZone(utc);
            return encodeGeneralizedTime(genFormat.format(date));
        } else {
            SimpleDateFormat utcFormat = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
            utcFormat.setTimeZone(utc);
            return encodeUtcTime(utcFormat.format(date));
        }
    }

    // ASN.1 DER primitives
    private static byte[] encodeSequence(byte[] content) throws IOException {
        return encodeTlv(0x30, content);
    }

    private static byte[] encodeSet(byte[] content) throws IOException {
        return encodeTlv(0x31, content);
    }

    private static byte[] encodeExplicit(int tagNumber, byte[] content) throws IOException {
        return encodeTlv(0xA0 | (tagNumber & 0x1F), content);
    }

    private static byte[] encodeInteger(BigInteger val) throws IOException {
        return encodeTlv(0x02, val.toByteArray());
    }

    private static byte[] encodeBitString(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x00); // 0 unused bits
        out.write(data);
        return encodeTlv(0x03, out.toByteArray());
    }

    private static byte[] encodeUtf8String(String str) throws IOException {
        return encodeTlv(0x0C, str.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] encodePrintableString(String str) throws IOException {
        return encodeTlv(0x13, str.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] encodeUtcTime(String utcStr) throws IOException {
        return encodeTlv(0x17, utcStr.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] encodeGeneralizedTime(String genStr) throws IOException {
        return encodeTlv(0x18, genStr.getBytes(StandardCharsets.US_ASCII));
    }

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
