package com.developer.love.tool;

import com.developer.love.tool.conversion.AabSigner;
import com.developer.love.tool.conversion.AabValidator;
import com.developer.love.tool.conversion.BundleConverter;
import com.developer.love.tool.core.AppConstants;
import com.developer.love.tool.core.AppUtils;
import com.developer.love.tool.installedapps.AppInfoModel;
import com.developer.love.tool.installedapps.InstalledAppsManager;
import com.developer.love.tool.keystore.CertificateGenerator;
import com.developer.love.tool.keystore.KeystoreManager;
import com.developer.love.tool.keystore.KeystoreValidator;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class DevLoveToolUnitTest {

    @Test
    public void testKeystoreValidatorYears() {
        // Valid 100 years case
        KeystoreValidator.ValidationResult r1 = KeystoreValidator.validate(
                "my-key", "password123", "key0", "password123", "100",
                "Rahul Sharma", "Bharat Apps", "IN"
        );
        Assert.assertTrue(r1.isValid);

        // Zero years invalid
        KeystoreValidator.ValidationResult rZero = KeystoreValidator.validate(
                "my-key", "password123", "key0", "password123", "0",
                "Rahul Sharma", "Bharat Apps", "IN"
        );
        Assert.assertFalse(rZero.isValid);

        // > 1000 years invalid
        KeystoreValidator.ValidationResult rTooHigh = KeystoreValidator.validate(
                "my-key", "password123", "key0", "password123", "1001",
                "Rahul Sharma", "Bharat Apps", "IN"
        );
        Assert.assertFalse(rTooHigh.isValid);

        // Short password
        KeystoreValidator.ValidationResult r2 = KeystoreValidator.validate(
                "my-key", "123", "key0", "password123", "100",
                "Rahul Sharma", "Bharat Apps", "IN"
        );
        Assert.assertFalse(r2.isValid);

        // Invalid country code
        KeystoreValidator.ValidationResult r3 = KeystoreValidator.validate(
                "my-key", "password123", "key0", "password123", "100",
                "Rahul Sharma", "Bharat Apps", "IND"
        );
        Assert.assertFalse(r3.isValid);

        // Missing filename
        KeystoreValidator.ValidationResult r4 = KeystoreValidator.validate(
                "", "password123", "key0", "password123", "100",
                "Rahul Sharma", "Bharat Apps", "IN"
        );
        Assert.assertFalse(r4.isValid);
    }

    @Test
    public void testCertificate100YearsAndJksPasswordlessAliasExtraction() throws Exception {
        KeyPair kp = CertificateGenerator.generateRSAKeyPair(2048);
        Assert.assertNotNull(kp);

        CertificateGenerator.CertParams params = new CertificateGenerator.CertParams();
        params.commonName = "Rahul Sharma";
        params.organization = "Bharat Apps";
        params.organizationalUnit = "Mobile";
        params.locality = "Bengaluru";
        params.state = "Karnataka";
        params.countryCode = "IN";
        params.validityYears = 100;

        X509Certificate cert = CertificateGenerator.generateSelfSignedCertificate(kp, params);
        Assert.assertNotNull(cert);
        Assert.assertTrue(cert.getSubjectX500Principal().getName().contains("Rahul Sharma"));
        Assert.assertTrue(cert.getIssuerX500Principal().getName().contains("Rahul Sharma"));

        // Verify 100-year GeneralizedTime expiry is actually ~100 years in the future (post-2050)
        Calendar calBefore = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calBefore.setTime(cert.getNotBefore());
        Calendar calAfter = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calAfter.setTime(cert.getNotAfter());
        int yearDiff = calAfter.get(Calendar.YEAR) - calBefore.get(Calendar.YEAR);
        Assert.assertTrue("Expected ~100 years validity, got " + yearDiff, yearDiff >= 99 && yearDiff <= 101);
        Assert.assertTrue(cert.getNotAfter().after(cert.getNotBefore()));
        cert.checkValidity(); // Must be currently valid (not wrapped to 19xx/2026!)

        String sha256 = AppUtils.getFingerprint(cert.getEncoded(), "SHA-256");
        Assert.assertNotNull(sha256);
        Assert.assertTrue(sha256.contains(":"));

        // Create PKCS12 KeyStore and test loading
        KeyStore p12 = KeyStore.getInstance("PKCS12");
        p12.load(null, null);
        p12.setKeyEntry("key0", kp.getPrivate(), "storepass".toCharArray(), new Certificate[]{cert});

        File tempP12 = File.createTempFile("test_keystore", ".p12");
        tempP12.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(tempP12)) {
            p12.store(fos, "storepass".toCharArray());
        }

        KeyStore loadedP12 = KeystoreManager.loadKeystore(tempP12, "storepass");
        Assert.assertTrue(loadedP12.containsAlias("key0"));
        Assert.assertTrue(KeystoreManager.extractAliases(tempP12, "storepass").contains("key0"));

        // Create JKS KeyStore and verify passwordless alias extraction!
        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(null, null);
        jks.setKeyEntry("bharat_release_key", kp.getPrivate(), "secret123".toCharArray(), new Certificate[]{cert});

        File tempJks = File.createTempFile("test_release", ".jks");
        tempJks.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(tempJks)) {
            jks.store(fos, "secret123".toCharArray());
        }

        List<String> passwordlessAliases = KeystoreManager.extractAliases(tempJks, "");
        Assert.assertEquals(1, passwordlessAliases.size());
        Assert.assertEquals("bharat_release_key", passwordlessAliases.get(0));
    }

    @Test
    public void testInstalledAppsFilteringAndSorting() {
        List<AppInfoModel> list = new ArrayList<>();

        AppInfoModel app1 = new AppInfoModel();
        app1.setAppName("Zeta Tool");
        app1.setPackageName("com.zeta.app");
        app1.setSystemApp(false);
        app1.setAppSize(1000);
        list.add(app1);

        AppInfoModel app2 = new AppInfoModel();
        app2.setAppName("Alpha Studio");
        app2.setPackageName("com.alpha.app");
        app2.setSystemApp(false);
        app2.setAppSize(5000);
        list.add(app2);

        AppInfoModel sysApp = new AppInfoModel();
        sysApp.setAppName("System Service");
        sysApp.setPackageName("com.android.system");
        sysApp.setSystemApp(true);
        sysApp.setAppSize(2000);
        list.add(sysApp);

        List<AppInfoModel> userOnly = InstalledAppsManager.filterAndSort(
                list, "", AppConstants.FILTER_USER_ONLY, AppConstants.SORT_ALPHA_ASC
        );
        Assert.assertEquals(2, userOnly.size());
        Assert.assertEquals("Alpha Studio", userOnly.get(0).getAppName());
        Assert.assertEquals("Zeta Tool", userOnly.get(1).getAppName());

        List<AppInfoModel> sizeSorted = InstalledAppsManager.filterAndSort(
                list, "", AppConstants.FILTER_USER_ONLY, AppConstants.SORT_SIZE_DESC
        );
        Assert.assertEquals("Alpha Studio", sizeSorted.get(0).getAppName());

        List<AppInfoModel> searched = InstalledAppsManager.filterAndSort(
                list, "zeta", AppConstants.FILTER_USER_ONLY, AppConstants.SORT_ALPHA_ASC
        );
        Assert.assertEquals(1, searched.size());
        Assert.assertEquals("Zeta Tool", searched.get(0).getAppName());

        app1.setFirstInstallTime(1000L);
        app1.setLastUpdateTime(5000L); // Recently updated
        app2.setFirstInstallTime(3000L);
        app2.setLastUpdateTime(3000L);
        List<AppInfoModel> recentSorted = InstalledAppsManager.filterAndSort(
                list, "", AppConstants.FILTER_USER_ONLY, AppConstants.SORT_RECENT_INSTALLED
        );
        Assert.assertEquals(2, recentSorted.size());
        Assert.assertEquals("Zeta Tool", recentSorted.get(0).getAppName());
        Assert.assertEquals("Alpha Studio", recentSorted.get(1).getAppName());
    }

    @Test
    public void testAabSigningAndValidation() throws Exception {
        File tempZip = File.createTempFile("test_archive", ".zip");
        tempZip.deleteOnExit();

        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(tempZip))) {
            ZipEntry e1 = new ZipEntry("base/manifest/AndroidManifest.xml");
            zos.putNextEntry(e1);
            zos.write("<manifest/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            ZipEntry e2 = new ZipEntry("base/dex/classes.dex");
            zos.putNextEntry(e2);
            zos.write("dex035".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        KeyPair kp = CertificateGenerator.generateRSAKeyPair(2048);
        CertificateGenerator.CertParams p = new CertificateGenerator.CertParams();
        p.commonName = "Signer";
        p.organization = "Org";
        p.countryCode = "IN";
        p.validityYears = 100;
        X509Certificate cert = CertificateGenerator.generateSelfSignedCertificate(kp, p);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("signerkey", kp.getPrivate(), "pass123".toCharArray(), new Certificate[]{cert});

        File outDir = tempZip.getParentFile();
        AabSigner.SigningResult signResult = AabSigner.signArchive(
                tempZip, outDir, "signed_test.aab", ks, "signerkey", "pass123"
        );

        Assert.assertTrue(signResult.errorMessage != null ? signResult.errorMessage : "Success expected", signResult.isSuccess);
        Assert.assertNotNull(signResult.signedFile);
        Assert.assertTrue(signResult.signedFile.exists());

        AabValidator.ValidationResult valResult = AabValidator.verifySignedArchive(signResult.signedFile, cert);
        Assert.assertTrue(valResult.isValid);
        Assert.assertTrue(valResult.hasManifest);
        Assert.assertTrue(valResult.hasSignatureFile);
        Assert.assertTrue(valResult.hasSignatureBlock);
        Assert.assertTrue(valResult.verifiedEntriesCount >= 2);
    }

    @Test
    public void testBundleMetadataAndProtoXmlAndStanzaSigning() throws Exception {
        // Verify BundleConfig.pb, native.pb, assets.pb protobuf encoding
        byte[] bundleConfig = com.developer.love.tool.conversion.BundleMetadataWriter.buildBundleConfigPb();
        Assert.assertTrue(bundleConfig.length > 50);
        // Field 1 (Bundletool) tag = 0x0A
        Assert.assertEquals(0x0A, bundleConfig[0] & 0xFF);

        java.util.Set<String> abis = new java.util.TreeSet<>();
        abis.add("lib/arm64-v8a");
        abis.add("lib/armeabi-v7a");
        byte[] nativePb = com.developer.love.tool.conversion.BundleMetadataWriter.buildNativePb(abis);
        Assert.assertTrue(nativePb.length > 20);

        java.util.Set<String> assets = new java.util.TreeSet<>();
        assets.add("assets");
        byte[] assetsPb = com.developer.love.tool.conversion.BundleMetadataWriter.buildAssetsPb(assets);
        Assert.assertTrue(assetsPb.length > 5);

        // Verify BundleConverter handles raw XMLs in res/raw/ without corrupting them
        File tempApk = File.createTempFile("sample_input", ".apk");
        tempApk.deleteOnExit();
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(tempApk))) {
            zos.putNextEntry(new ZipEntry("classes.dex"));
            zos.write("dex035".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("res/raw/keep.xml"));
            zos.write("<resources/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("assets/info.txt"));
            zos.write("hello".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("lib/arm64-v8a/libdemo.so"));
            zos.write(new byte[]{0x7F, 'E', 'L', 'F'});
            zos.closeEntry();
        }

        BundleConverter.ConversionReport report = BundleConverter.evaluateAndReconstruct(
                tempApk, tempApk.getParentFile(), "sample_out.aab"
        );
        Assert.assertNull(report.errorMessage);
        Assert.assertTrue(report.isFeasibleWithoutAapt2);
        Assert.assertNotNull(report.reconstructedArchive);

        try (java.util.zip.ZipFile outZip = new java.util.zip.ZipFile(report.reconstructedArchive)) {
            Assert.assertNotNull(outZip.getEntry("BundleConfig.pb"));
            Assert.assertNotNull(outZip.getEntry("base/native.pb"));
            Assert.assertNotNull(outZip.getEntry("base/assets.pb"));
            Assert.assertNotNull(outZip.getEntry("base/dex/classes.dex"));
            Assert.assertNotNull(outZip.getEntry("base/res/raw/keep.xml"));
        }
    }

    @Test
    public void testEncryptedPkcs12PasswordAliasFetchAndPureJavaJksLoader() throws Exception {
        KeyPair kp = CertificateGenerator.generateRSAKeyPair(2048);
        CertificateGenerator.CertParams p = new CertificateGenerator.CertParams();
        p.commonName = "Jharkhand Poly";
        p.organization = "Polytechnic";
        p.countryCode = "IN";
        p.validityYears = 100;
        X509Certificate cert = CertificateGenerator.generateSelfSignedCertificate(kp, p);

        // 1. PKCS12 saved with .jks extension (standard Android Studio / Java 9+ behavior)
        KeyStore p12 = KeyStore.getInstance("PKCS12");
        p12.load(null, null);
        p12.setKeyEntry("poly_alias", kp.getPrivate(), "mySecret@123".toCharArray(), new Certificate[]{cert});

        File tempP12AsJks = File.createTempFile("imported_pkcs12", ".jks");
        tempP12AsJks.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(tempP12AsJks)) {
            p12.store(fos, "mySecret@123".toCharArray());
        }

        // Wrong password must fail to unlock; empty password either fails (encrypted SafeContents) or returns the valid alias
        Assert.assertTrue(KeystoreManager.extractAliases(tempP12AsJks, "wrongpass").isEmpty());
        // Correct password always fetches the alias!
        List<String> fetched = KeystoreManager.extractAliases(tempP12AsJks, "mySecret@123");
        Assert.assertEquals(1, fetched.size());
        Assert.assertEquals("poly_alias", fetched.get(0));

        // 2. Classic Sun JKS (0xFEEDFEED) with DIFFERENT store & key passwords
        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(null, null);
        jks.setKeyEntry("jks_alias", kp.getPrivate(), "keyPass999".toCharArray(), new Certificate[]{cert});

        File tempJks = File.createTempFile("classic_sun", ".jks");
        tempJks.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(tempJks)) {
            jks.store(fos, "storePass111".toCharArray());
        }

        Assert.assertTrue(KeystoreManager.isJksBinaryFormat(tempJks));
        KeyStore pureLoaded = KeystoreManager.loadJksPureJava(
                tempJks, "storePass111".toCharArray(), "jks_alias", "keyPass999".toCharArray()
        );
        Assert.assertTrue(pureLoaded.containsAlias("jks_alias"));
        Assert.assertNotNull(pureLoaded.getKey("jks_alias", "keyPass999".toCharArray()));
    }

    @Test
    public void testCesu8ModifiedUtf8ResStringPoolDecoding() {
        // Build minimal RES_STRING_POOL_TYPE chunk (UTF-8 flag = 0x100) with "Hi 🚀 📁"
        // CESU-8 bytes for 🚀 (U+1F680 = D83D DE80): ED A0 BD ED BA 80; standard 4-byte UTF-8 for 📁 (U+1F4C1): F0 9F 93 81
        byte[] strBytes = new byte[]{
                8, // UTF-16 code unit length
                14, // byte length (3 + 6 + 1 + 4)
                'H', 'i', ' ',
                (byte) 0xED, (byte) 0xA0, (byte) 0xBD, (byte) 0xED, (byte) 0xBA, (byte) 0x80,
                ' ',
                (byte) 0xF0, (byte) 0x9F, (byte) 0x93, (byte) 0x81,
                0x00
        };
        int headerSize = 28;
        int stringsStart = headerSize + 4;
        int chunkSize = stringsStart + strBytes.length;
        java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(chunkSize).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) 0x0001);
        bb.putShort((short) headerSize);
        bb.putInt(chunkSize);
        bb.putInt(1); // stringCount
        bb.putInt(0); // styleCount
        bb.putInt(1 << 8); // UTF8_FLAG
        bb.putInt(stringsStart);
        bb.putInt(0);
        bb.putInt(0); // offset[0] = 0
        bb.put(strBytes);

        com.developer.love.tool.conversion.ResStringPoolReader pool =
                com.developer.love.tool.conversion.ResStringPoolReader.parse(bb.array(), 0);
        Assert.assertEquals(1, pool.size());
        Assert.assertEquals("Hi 🚀 📁", pool.getString(0));
    }

    @Test
    public void testResItemIdNullRefAndDimensions() {
        // <item type="id"> in resources.arsc is TYPE_INT_BOOLEAN (0x12) with data=0 -> Item.id (field 6: tag=0x32, len=0)
        byte[] idItem = com.developer.love.tool.conversion.ResItemProtoEncoder.encodeItem(
                com.developer.love.tool.conversion.ResItemProtoEncoder.TYPE_INT_BOOLEAN,
                0,
                "id",
                null,
                0x7F,
                null,
                null,
                null
        );
        Assert.assertArrayEquals(new byte[]{0x32, 0x00}, idItem);

        // @null reference: TYPE_REFERENCE with data=0 -> Item.ref (field 1: tag=0x0A, len=0)
        byte[] nullRefItem = com.developer.love.tool.conversion.ResItemProtoEncoder.encodeItem(
                com.developer.love.tool.conversion.ResItemProtoEncoder.TYPE_REFERENCE,
                0,
                "style",
                null,
                0x7F,
                null,
                null,
                null
        );
        Assert.assertArrayEquals(new byte[]{0x0A, 0x00}, nullRefItem);

        // 16dp complex value (mantissa=16 -> 16<<8, radix=0, unit=1 dp)
        String dimStr = com.developer.love.tool.conversion.ResItemProtoEncoder.formatAttributeDisplayValue(
                com.developer.love.tool.conversion.ResItemProtoEncoder.TYPE_DIMENSION,
                (16 << 8) | 1,
                null,
                null,
                0x7F,
                null
        );
        Assert.assertEquals("16dp", dimStr);
    }

    @Test
    public void testEcAndDsaSigningAndNegativeTamperRejection() throws Exception {
        File unsignedZip = File.createTempFile("unsigned_tamper", ".zip");
        unsignedZip.deleteOnExit();
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(unsignedZip))) {
            zos.putNextEntry(new ZipEntry("base/manifest/AndroidManifest.xml"));
            zos.write(new byte[]{0x0A, 0x02, 0x1A, 0x00});
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("base/dex/classes.dex"));
            zos.write("dex035-payload".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        // 1. Sign & verify with EC (ECDSA SHA256withECDSA)
        java.security.KeyPairGenerator ecGen = java.security.KeyPairGenerator.getInstance("EC");
        ecGen.initialize(256);
        KeyPair ecKp = ecGen.generateKeyPair();
        X509Certificate ecCert = generateTestCert(ecKp, "SHA256withECDSA", "CN=EC Signer, O=Org, C=IN");

        KeyStore ecKs = KeyStore.getInstance("PKCS12");
        ecKs.load(null, null);
        ecKs.setKeyEntry("eckey", ecKp.getPrivate(), "pass".toCharArray(), new Certificate[]{ecCert});

        AabSigner.SigningResult ecSign = AabSigner.signArchive(
                unsignedZip, unsignedZip.getParentFile(), "ec_signed.aab", ecKs, "eckey", "pass"
        );
        Assert.assertTrue(ecSign.errorMessage, ecSign.isSuccess);
        ecSign.signedFile.deleteOnExit();
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(ecSign.signedFile)) {
            Assert.assertNotNull(zf.getEntry("META-INF/ECKEY.EC"));
        }
        AabValidator.ValidationResult ecVal = AabValidator.verifySignedArchive(ecSign.signedFile, ecCert);
        Assert.assertTrue(ecVal.errorMessage, ecVal.isValid);

        // 2. Sign & verify with DSA (SHA256withDSA)
        java.security.KeyPairGenerator dsaGen = java.security.KeyPairGenerator.getInstance("DSA");
        dsaGen.initialize(2048);
        KeyPair dsaKp = dsaGen.generateKeyPair();
        X509Certificate dsaCert = generateTestCert(dsaKp, "SHA256withDSA", "CN=DSA Signer, O=Org, C=IN");

        KeyStore dsaKs = KeyStore.getInstance("JKS");
        dsaKs.load(null, null);
        dsaKs.setKeyEntry("dsakey", dsaKp.getPrivate(), "pass".toCharArray(), new Certificate[]{dsaCert});

        AabSigner.SigningResult dsaSign = AabSigner.signArchive(
                unsignedZip, unsignedZip.getParentFile(), "dsa_signed.aab", dsaKs, "dsakey", "pass"
        );
        Assert.assertTrue(dsaSign.errorMessage, dsaSign.isSuccess);
        dsaSign.signedFile.deleteOnExit();
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(dsaSign.signedFile)) {
            Assert.assertNotNull(zf.getEntry("META-INF/DSAKEY.DSA"));
        }
        AabValidator.ValidationResult dsaVal = AabValidator.verifySignedArchive(dsaSign.signedFile, dsaCert);
        Assert.assertTrue(dsaVal.errorMessage, dsaVal.isValid);

        // 3. Wrong expected certificate MUST FAIL validation
        AabValidator.ValidationResult wrongCertVal = AabValidator.verifySignedArchive(ecSign.signedFile, dsaCert);
        Assert.assertFalse(wrongCertVal.isValid);

        // 4. Tampered payload entry MUST FAIL validation
        File tamperedPayload = tamperZip(ecSign.signedFile, "base/dex/classes.dex",
                "HACKED".getBytes(StandardCharsets.UTF_8), null);
        Assert.assertFalse(AabValidator.verifySignedArchive(tamperedPayload, ecCert).isValid);

        // 5. Added unsigned entry MUST FAIL validation
        File addedUnsigned = tamperZip(ecSign.signedFile, null, null, "base/assets/injected.txt");
        Assert.assertFalse(AabValidator.verifySignedArchive(addedUnsigned, ecCert).isValid);

        // 6. Tampered .EC signature block MUST FAIL validation
        File tamperedSig = tamperZip(ecSign.signedFile, "META-INF/ECKEY.EC", new byte[]{0x30, 0x00}, null);
        Assert.assertFalse(AabValidator.verifySignedArchive(tamperedSig, ecCert).isValid);
    }

    @Test
    public void testCorruptKeystoreAndZipSlipSafeguards() throws Exception {
        // Corrupt file must throw exception (never hang or succeed)
        File corruptKs = File.createTempFile("corrupt", ".jks");
        corruptKs.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(corruptKs)) {
            fos.write("not-a-valid-keystore".getBytes(StandardCharsets.UTF_8));
        }
        Assert.assertTrue(KeystoreManager.extractAliases(corruptKs, "pass").isEmpty());
        boolean threw = false;
        try {
            KeystoreManager.loadKeystore(corruptKs, "pass");
        } catch (Exception expected) {
            threw = true;
        }
        Assert.assertTrue(threw);

        // Zip-Slip path traversal in APK must be rejected cleanly
        File zipSlipApk = File.createTempFile("zipslip", ".apk");
        zipSlipApk.deleteOnExit();
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipSlipApk))) {
            zos.putNextEntry(new ZipEntry("../../evil.txt"));
            zos.write("bad".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        BundleConverter.ConversionReport slipReport = BundleConverter.evaluateAndReconstruct(
                zipSlipApk, zipSlipApk.getParentFile(), "slip_out.aab"
        );
        Assert.assertNotNull(slipReport.errorMessage);
        Assert.assertNull(slipReport.reconstructedArchive);
    }

    private static File tamperZip(File srcZip, String replaceEntry, byte[] newBytes, String extraEntry) throws Exception {
        File out = File.createTempFile("tamper", ".aab");
        out.deleteOnExit();
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(srcZip);
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(out))) {
            java.util.Enumeration<? extends ZipEntry> entries = zf.entries();
            byte[] buf = new byte[4096];
            while (entries.hasMoreElements()) {
                ZipEntry ze = entries.nextElement();
                zos.putNextEntry(new ZipEntry(ze.getName()));
                if (replaceEntry != null && replaceEntry.equals(ze.getName())) {
                    zos.write(newBytes);
                } else {
                    try (java.io.InputStream is = zf.getInputStream(ze)) {
                        int r;
                        while ((r = is.read(buf)) != -1) zos.write(buf, 0, r);
                    }
                }
                zos.closeEntry();
            }
            if (extraEntry != null) {
                zos.putNextEntry(new ZipEntry(extraEntry));
                zos.write("unsigned".getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
        }
        return out;
    }

    private static X509Certificate generateTestCert(KeyPair kp, String sigAlg, String dn) throws Exception {
        java.math.BigInteger serial = new java.math.BigInteger(64, new java.security.SecureRandom()).abs().add(java.math.BigInteger.ONE);
        java.util.Date notBefore = new java.util.Date(System.currentTimeMillis() - 60000L);
        java.util.Date notAfter = new java.util.Date(System.currentTimeMillis() + 365L * 86400000L);
        javax.security.auth.x500.X500Principal principal = new javax.security.auth.x500.X500Principal(dn);

        // Build X.509 v3 TBSCertificate in pure Java using CertificateGenerator helper OIDs via reflection-free DER
        byte[] tbs = buildMinimalTbsCert(serial, sigAlg, principal, notBefore, notAfter, kp.getPublic().getEncoded());
        java.security.Signature sig = java.security.Signature.getInstance(sigAlg);
        sig.initSign(kp.getPrivate());
        sig.update(tbs);
        byte[] sigBytes = sig.sign();

        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        baos.write(tbs);
        baos.write(encodeAlgIdForTest(sigAlg));
        byte[] bitStr = new byte[sigBytes.length + 1];
        System.arraycopy(sigBytes, 0, bitStr, 1, sigBytes.length);
        baos.write(derTlv(0x03, bitStr));
        byte[] fullCert = derTlv(0x30, baos.toByteArray());
        return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(fullCert));
    }

    private static byte[] buildMinimalTbsCert(
            java.math.BigInteger serial,
            String sigAlg,
            javax.security.auth.x500.X500Principal owner,
            java.util.Date notBefore,
            java.util.Date notAfter,
            byte[] spki
    ) throws Exception {
        java.io.ByteArrayOutputStream tbs = new java.io.ByteArrayOutputStream();
        tbs.write(derTlv(0xA0, derTlv(0x02, new byte[]{0x02}))); // v3
        tbs.write(derTlv(0x02, serial.toByteArray()));
        tbs.write(encodeAlgIdForTest(sigAlg));
        tbs.write(owner.getEncoded());

        java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("yyMMddHHmmss'Z'", java.util.Locale.US);
        fmt.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        java.io.ByteArrayOutputStream val = new java.io.ByteArrayOutputStream();
        val.write(derTlv(0x17, fmt.format(notBefore).getBytes(StandardCharsets.US_ASCII)));
        val.write(derTlv(0x17, fmt.format(notAfter).getBytes(StandardCharsets.US_ASCII)));
        tbs.write(derTlv(0x30, val.toByteArray()));
        tbs.write(owner.getEncoded());
        tbs.write(spki);
        return derTlv(0x30, tbs.toByteArray());
    }

    private static byte[] encodeAlgIdForTest(String sigAlg) throws Exception {
        if ("SHA256withECDSA".equals(sigAlg)) {
            return derTlv(0x30, new byte[]{0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02});
        }
        return derTlv(0x30, new byte[]{0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02});
    }

    private static byte[] derTlv(int tag, byte[] content) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(tag);
        int len = content.length;
        if (len < 128) {
            out.write(len);
        } else if (len < 256) {
            out.write(0x81);
            out.write(len);
        } else {
            out.write(0x82);
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        out.write(content);
        return out.toByteArray();
    }
}
