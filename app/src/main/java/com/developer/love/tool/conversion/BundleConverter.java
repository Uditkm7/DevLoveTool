package com.developer.love.tool.conversion;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class BundleConverter {

    public static class ConversionReport {
        public boolean isFeasibleWithoutAapt2;
        public String technicalAnalysis;
        public File reconstructedArchive;
        public int entriesReconstructed;
        public int protoXmlCount;
        public long archiveSize;
        public String errorMessage;
    }

    public static ConversionReport evaluateAndReconstruct(File apkFile, File outputDir, String outputBaseName) {
        ConversionReport report = new ConversionReport();
        if (apkFile == null || !apkFile.exists()) {
            report.errorMessage = "Source APK file not found.";
            return report;
        }
        if (outputDir == null) {
            report.errorMessage = "Output directory is unavailable.";
            return report;
        }
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        String bundleName = (outputBaseName != null && !outputBaseName.trim().isEmpty())
                ? outputBaseName.trim()
                : "temp_bundle.aab";
        if (!bundleName.toLowerCase(Locale.US).endsWith(".aab")
                && !bundleName.toLowerCase(Locale.US).endsWith(".zip")) {
            bundleName = bundleName + ".aab";
        }
        File outputFile = new File(outputDir, bundleName);

        try {
            try (ZipFile zipIn = new ZipFile(apkFile)) {
                // Pass 1: Inventory APK entries, detect native/asset directories, identify binary XMLs in res/, read resources.arsc
                Set<String> allApkEntries = new HashSet<>();
                Set<String> xmlResEntries = new HashSet<>();
                Set<String> nativeAbiDirs = new TreeSet<>();
                Set<String> assetDirs = new TreeSet<>();
                byte[] arscBytes = null;
                byte[] existingResourcesPb = null;
                boolean hasManifest = false;

                Enumeration<? extends ZipEntry> scanEnum = zipIn.entries();
                while (scanEnum.hasMoreElements()) {
                    ZipEntry ze = scanEnum.nextElement();
                    if (ze.isDirectory()) continue;
                    String name = ze.getName();
                    if (name == null || name.isEmpty() || isUnsafeZipPath(name)) continue;
                    allApkEntries.add(name);

                    if ("AndroidManifest.xml".equals(name)) {
                        hasManifest = true;
                    } else if ("resources.arsc".equals(name)) {
                        arscBytes = readEntryBytes(zipIn, ze);
                    } else if ("resources.pb".equals(name)) {
                        existingResourcesPb = readEntryBytes(zipIn, ze);
                    } else if (name.startsWith("res/") && name.toLowerCase(Locale.US).endsWith(".xml")) {
                        if (isEntryBinaryXml(zipIn, ze)) {
                            xmlResEntries.add(name);
                        }
                    } else if (name.startsWith("lib/")) {
                        int secondSlash = name.indexOf('/', 4);
                        if (secondSlash > 4) {
                            nativeAbiDirs.add(name.substring(0, secondSlash));
                        }
                    } else if (name.startsWith("assets/")) {
                        int lastSlash = name.lastIndexOf('/');
                        String dir = lastSlash > 0 ? name.substring(0, lastSlash) : "assets";
                        assetDirs.add(dir);
                    }
                }

                if (!hasManifest && arscBytes == null && allApkEntries.isEmpty()) {
                    throw new IllegalArgumentException("Source archive is empty or not a valid APK.");
                }

                // Compile resources.arsc -> base/resources.pb (and collect resource ID -> name symbol table)
                int appPackageId = 0x7F;
                Map<Integer, String> resIdToName = new LinkedHashMap<>();
                byte[] resourcesPbBytes = existingResourcesPb;
                if (resourcesPbBytes == null && arscBytes != null) {
                    ArscToProtoConverter.ConversionOutput arscOut = ArscToProtoConverter.convert(
                            arscBytes, xmlResEntries, allApkEntries
                    );
                    resourcesPbBytes = arscOut.resourcesPb;
                    appPackageId = arscOut.appPackageId;
                    resIdToName = arscOut.resIdToName;
                }

                // Pass 2: Assemble Protobuf Android App Bundle (.aab)
                int count = 0;
                int protoXmlConverted = 0;

                try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(outputFile))) {
                    // 1. BundleConfig.pb
                    writeEntry(zipOut, "BundleConfig.pb", BundleMetadataWriter.buildBundleConfigPb(), 0);
                    count++;

                    // 2. base/resources.pb
                    if (resourcesPbBytes != null && resourcesPbBytes.length > 0) {
                        writeEntry(zipOut, "base/resources.pb", resourcesPbBytes, 0);
                        count++;
                    }

                    // 3. base/native.pb (required when base/lib/ contains .so files)
                    if (!nativeAbiDirs.isEmpty()) {
                        byte[] nativePb = BundleMetadataWriter.buildNativePb(nativeAbiDirs);
                        if (nativePb.length > 0) {
                            writeEntry(zipOut, "base/native.pb", nativePb, 0);
                            count++;
                        }
                    }

                    // 4. base/assets.pb (required when base/assets/ contains files)
                    if (!assetDirs.isEmpty()) {
                        byte[] assetsPb = BundleMetadataWriter.buildAssetsPb(assetDirs);
                        if (assetsPb.length > 0) {
                            writeEntry(zipOut, "base/assets.pb", assetsPb, 0);
                            count++;
                        }
                    }

                    // 5. Convert & copy APK payload entries
                    Enumeration<? extends ZipEntry> entries = zipIn.entries();
                    byte[] buffer = new byte[16384];
                    Set<String> writtenNames = new LinkedHashSet<>();

                    while (entries.hasMoreElements()) {
                        ZipEntry srcEntry = entries.nextElement();
                        if (srcEntry.isDirectory()) continue;
                        String name = srcEntry.getName();
                        if (name == null || name.isEmpty() || isUnsafeZipPath(name)) continue;

                        // Skip APK JAR signature files & resources.arsc (replaced by resources.pb)
                        if (isApkSignatureEntry(name) || "resources.arsc".equals(name) || "resources.pb".equals(name)) {
                            continue;
                        }

                        if ("AndroidManifest.xml".equals(name)) {
                            String manifestDest = "base/manifest/AndroidManifest.xml";
                            if (!writtenNames.add(manifestDest)) continue;
                            byte[] rawManifest = readEntryBytes(zipIn, srcEntry);
                            byte[] protoManifest = BinaryXmlToProtoConverter.isBinaryXml(rawManifest)
                                    ? BinaryXmlToProtoConverter.convert(rawManifest, appPackageId, resIdToName)
                                    : rawManifest;
                            writeEntry(zipOut, manifestDest, protoManifest, srcEntry.getTime());
                            protoXmlConverted++;
                            count++;
                            continue;
                        }

                        if (xmlResEntries.contains(name)) {
                            String resXmlDest = "base/" + name;
                            if (!writtenNames.add(resXmlDest)) continue;
                            byte[] rawXml = readEntryBytes(zipIn, srcEntry);
                            byte[] protoXml = BinaryXmlToProtoConverter.convert(rawXml, appPackageId, resIdToName);
                            writeEntry(zipOut, resXmlDest, protoXml, srcEntry.getTime());
                            protoXmlConverted++;
                            count++;
                            continue;
                        }

                        String targetName;
                        if (!name.contains("/") && name.endsWith(".dex")) {
                            targetName = "base/dex/" + name;
                        } else if (name.startsWith("res/") || name.startsWith("assets/") || name.startsWith("lib/")) {
                            targetName = "base/" + name;
                        } else {
                            targetName = "base/root/" + name;
                        }

                        if (!writtenNames.add(targetName)) {
                            continue;
                        }

                        ZipEntry destEntry = new ZipEntry(targetName);
                        if (srcEntry.getTime() > 0) destEntry.setTime(srcEntry.getTime());
                        zipOut.putNextEntry(destEntry);
                        try (InputStream is = zipIn.getInputStream(srcEntry)) {
                            int read;
                            while ((read = is.read(buffer)) != -1) {
                                zipOut.write(buffer, 0, read);
                            }
                        }
                        zipOut.closeEntry();
                        count++;
                    }

                    zipOut.flush();
                }

                report.reconstructedArchive = outputFile;
                report.entriesReconstructed = count;
                report.protoXmlCount = protoXmlConverted;
                report.archiveSize = outputFile.length();
                report.isFeasibleWithoutAapt2 = true;

                StringBuilder analysis = new StringBuilder();
                analysis.append("BUNDLE COMPILATION REPORT:\n");
                analysis.append("• BundleConfig.pb: Compiled in standard Protocol Buffer format (bundletool 1.18.3 schema).\n");
                analysis.append("• Resource Table: ");
                if (resourcesPbBytes != null) {
                    analysis.append("Compiled resources.arsc -> base/resources.pb (aapt.pb.ResourceTable).\n");
                } else {
                    analysis.append("No resource table in source APK.\n");
                }
                analysis.append("• Proto XMLs: Converted ").append(protoXmlConverted).append(" binary XML files (AndroidManifest.xml & res/**/*.xml) to Protobuf XmlNode.\n");
                if (!nativeAbiDirs.isEmpty()) {
                    analysis.append("• Native Targeting: Generated base/native.pb for ").append(nativeAbiDirs.size()).append(" ABI directories.\n");
                }
                if (!assetDirs.isEmpty()) {
                    analysis.append("• Assets Targeting: Generated base/assets.pb for ").append(assetDirs.size()).append(" asset directories.\n");
                }
                analysis.append("• Cryptographic Signing: Ready for JAR v1 signing.");
                report.technicalAnalysis = analysis.toString();
            }
        } catch (Exception e) {
            if (outputFile.exists()) {
                outputFile.delete();
            }
            report.reconstructedArchive = null;
            report.errorMessage = "Bundle conversion failed: " + e.getMessage();
        }

        return report;
    }

    private static boolean isUnsafeZipPath(String name) {
        if (name.startsWith("/") || name.startsWith("\\")) return true;
        String[] parts = name.split("[/\\\\]");
        for (String p : parts) {
            if ("..".equals(p)) return true;
        }
        return false;
    }

    private static boolean isApkSignatureEntry(String name) {
        if (!name.startsWith("META-INF/")) return false;
        String upper = name.toUpperCase(Locale.US);
        if ("META-INF/MANIFEST.MF".equals(upper)) return true;
        if (upper.endsWith(".SF") || upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC")) {
            return true;
        }
        return upper.startsWith("META-INF/CERT.") || upper.startsWith("META-INF/SIG-");
    }

    private static boolean isEntryBinaryXml(ZipFile zipIn, ZipEntry ze) {
        byte[] header = new byte[8];
        try (InputStream is = zipIn.getInputStream(ze)) {
            int total = 0;
            while (total < 8) {
                int r = is.read(header, total, 8 - total);
                if (r < 0) break;
                total += r;
            }
            if (total < 8) return false;
            return BinaryXmlToProtoConverter.isBinaryXml(header);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] readEntryBytes(ZipFile zipIn, ZipEntry ze) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        try (InputStream is = zipIn.getInputStream(ze)) {
            int r;
            while ((r = is.read(buf)) != -1) {
                baos.write(buf, 0, r);
            }
        }
        return baos.toByteArray();
    }

    private static void writeEntry(ZipOutputStream zipOut, String name, byte[] data, long time) throws Exception {
        ZipEntry entry = new ZipEntry(name);
        if (time > 0) entry.setTime(time);
        zipOut.putNextEntry(entry);
        zipOut.write(data);
        zipOut.closeEntry();
    }
}
