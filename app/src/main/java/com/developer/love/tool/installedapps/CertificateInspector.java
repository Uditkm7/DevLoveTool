package com.developer.love.tool.installedapps;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import com.developer.love.tool.core.AppUtils;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CertificateInspector {

    public static class CertInfo {
        public String subject;
        public String issuer;
        public String serialNumber;
        public String validFrom;
        public String validTo;
        public String sha256;
        public String sha1;
        public String md5;
        public String signatureAlgorithm;
        public boolean isPastCertificate;
    }

    public static class CertResult {
        public List<CertInfo> activeCertificates = new ArrayList<>();
        public List<CertInfo> historyCertificates = new ArrayList<>();
        public String errorMessage;
    }

    public static CertResult inspect(Context context, String packageName) {
        CertResult result = new CertResult();
        PackageManager pm = context.getPackageManager();

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo signingInfo = pi.signingInfo;
                if (signingInfo == null) {
                    result.errorMessage = "No SigningInfo found for package.";
                    return result;
                }

                Signature[] activeSignatures;
                if (signingInfo.hasMultipleSigners()) {
                    activeSignatures = signingInfo.getApkContentsSigners();
                } else {
                    activeSignatures = signingInfo.getSigningCertificateHistory();
                }

                if (activeSignatures != null && activeSignatures.length > 0) {
                    // In single signer mode, getSigningCertificateHistory returns history with latest cert at index activeSignatures.length - 1 or 0
                    // But if hasMultipleSigners, getApkContentsSigners gives all active signers
                    if (signingInfo.hasMultipleSigners()) {
                        for (Signature sig : activeSignatures) {
                            CertInfo info = parseSignature(cf, sig, false);
                            if (info != null) result.activeCertificates.add(info);
                        }
                    } else {
                        // Single signer with potential history
                        Signature[] history = signingInfo.getSigningCertificateHistory();
                        if (history != null && history.length > 0) {
                            // The current active cert is the last or only one
                            Signature currentSig = history[history.length - 1];
                            CertInfo currentInfo = parseSignature(cf, currentSig, false);
                            if (currentInfo != null) result.activeCertificates.add(currentInfo);

                            // Previous history certificates if key rotation occurred
                            if (history.length > 1) {
                                for (int i = 0; i < history.length - 1; i++) {
                                    CertInfo pastInfo = parseSignature(cf, history[i], true);
                                    if (pastInfo != null) result.historyCertificates.add(pastInfo);
                                }
                            }
                        }
                    }
                }
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                @SuppressWarnings("deprecation")
                Signature[] signatures = pi.signatures;
                if (signatures != null) {
                    for (Signature sig : signatures) {
                        CertInfo info = parseSignature(cf, sig, false);
                        if (info != null) result.activeCertificates.add(info);
                    }
                }
            }

            if (result.activeCertificates.isEmpty()) {
                result.errorMessage = "No signing certificates could be extracted.";
            }

        } catch (Exception e) {
            result.errorMessage = "Inspection error: " + e.getMessage();
        }

        return result;
    }

    private static CertInfo parseSignature(CertificateFactory cf, Signature signature, boolean isPast) {
        try {
            byte[] bytes = signature.toByteArray();
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
            CertInfo info = new CertInfo();
            info.isPastCertificate = isPast;
            info.subject = cert.getSubjectX500Principal().getName();
            info.issuer = cert.getIssuerX500Principal().getName();
            info.serialNumber = cert.getSerialNumber().toString(16).toUpperCase();
            info.validFrom = AppUtils.formatDate(cert.getNotBefore().getTime());
            info.validTo = AppUtils.formatDate(cert.getNotAfter().getTime());
            byte[] encoded = cert.getEncoded();
            info.sha256 = AppUtils.getFingerprint(encoded, "SHA-256");
            info.sha1 = AppUtils.getFingerprint(encoded, "SHA-1");
            info.md5 = AppUtils.getFingerprint(encoded, "MD5");
            info.signatureAlgorithm = cert.getSigAlgName();
            return info;
        } catch (Exception e) {
            return null;
        }
    }
}
