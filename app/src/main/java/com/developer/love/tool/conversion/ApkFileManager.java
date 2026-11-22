package com.developer.love.tool.conversion;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import com.developer.love.tool.core.AppUtils;

public class ApkFileManager {

    public static class ApkAnalysis {
        public boolean isValidApk;
        public String fileName;
        public long fileSize;
        public String sha256;
        public boolean hasManifest;
        public boolean hasResourcesArsc;
        public int dexCount;
        public int assetCount;
        public int nativeLibCount;
        public int totalEntries;
        public List<String> signatureSchemes = new ArrayList<>();
        public String errorMessage;
    }

    public static ApkAnalysis analyzeApk(File file) {
        ApkAnalysis analysis = new ApkAnalysis();
        if (file == null || !file.exists()) {
            analysis.isValidApk = false;
            analysis.errorMessage = "File does not exist.";
            return analysis;
        }

        analysis.fileName = file.getName();
        analysis.fileSize = file.length();

        // Calculate SHA-256
        try (InputStream is = new FileInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[16384];
            int read;
            while ((read = is.read(buf)) != -1) {
                md.update(buf, 0, read);
            }
            analysis.sha256 = AppUtils.bytesToHexFormatted(md.digest());
        } catch (Exception e) {
            analysis.sha256 = "Calculation error";
        }

        // Parse ZIP structure
        try (ZipFile zip = new ZipFile(file)) {
            analysis.isValidApk = true;
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                analysis.totalEntries++;

                if (name.equals("AndroidManifest.xml")) {
                    analysis.hasManifest = true;
                } else if (name.equals("resources.arsc")) {
                    analysis.hasResourcesArsc = true;
                } else if (name.endsWith(".dex")) {
                    analysis.dexCount++;
                } else if (name.startsWith("lib/")) {
                    analysis.nativeLibCount++;
                } else if (name.startsWith("assets/")) {
                    analysis.assetCount++;
                } else if (name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                    if (!analysis.signatureSchemes.contains("JAR v1 (Signature Block)")) {
                        analysis.signatureSchemes.add("JAR v1 (Signature Block)");
                    }
                }
            }

            if (!analysis.hasManifest) {
                analysis.isValidApk = false;
                analysis.errorMessage = "Invalid APK: Missing AndroidManifest.xml.";
            }

        } catch (Exception e) {
            analysis.isValidApk = false;
            analysis.errorMessage = "Corrupt APK or invalid ZIP format: " + e.getMessage();
        }

        return analysis;
    }
}
