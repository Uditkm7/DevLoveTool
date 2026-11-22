package com.developer.love.tool.ui;

import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.HapticFeedbackConstants;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.activity.SystemBarStyle;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.developer.love.tool.R;
import com.developer.love.tool.core.AppConstants;
import com.developer.love.tool.core.AppUtils;
import com.developer.love.tool.installedapps.CertificateInspector;
import com.developer.love.tool.installedapps.ManifestInspector;
import com.developer.love.tool.storage.FileManager;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Single continuous vertical scroll view displaying all app specifications,
 * certificate details, permissions, and manifest components in clean 2-column selectable cards.
 */
public class AppDetailsActivity extends AppCompatActivity {

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private String packageName;

    // Header views
    private ImageView ivDetailIcon;
    private TextView tvDetailTitle;
    private TextView tvDetailSubtitle;

    // Overview 2-column views
    private TextView tvOvPackage;
    private TextView tvOvVersionName;
    private TextView tvOvVersionCode;
    private TextView tvOvSize;
    private TextView tvOvInstaller;
    private TextView tvOvFirstInstalled;
    private TextView tvOvLastUpdated;
    private TextView tvOvApkLocation;

    private MaterialButton btnLaunch;
    private MaterialButton btnSettings;
    private MaterialButton btnExport;

    // Certificate container
    private LinearLayout layoutCertContainer;

    // SDK & Permissions views
    private TextView tvMinSdk;
    private TextView tvTargetSdk;
    private TextView tvCompileSdk;
    private TextView tvPermissionsHeader;
    private LinearLayout layoutPermissionsList;

    // Components container
    private LinearLayout layoutComponentsContainer;

    private String apkSourceDir = null;
    private File pendingApkToSave = null;

    private final ActivityResultLauncher<String> saveApkLauncher = registerForActivityResult(
            new ActivityResultContracts.CreateDocument("application/vnd.android.package-archive"),
            uri -> {
                if (uri != null && pendingApkToSave != null) {
                    final File src = pendingApkToSave;
                    pendingApkToSave = null;
                    executor.execute(() -> {
                        try {
                            FileManager.copyFileToUri(this, src, uri);
                            runOnUiThread(() -> {
                                if (!isUiAlive()) return;
                                Toast.makeText(this, "APK saved to chosen folder!", Toast.LENGTH_LONG).show();
                            });
                        } catch (Exception e) {
                            runOnUiThread(() -> {
                                if (!isUiAlive()) return;
                                Toast.makeText(this, "Save failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                            });
                        }
                    });
                }
            }
    );

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        EdgeToEdge.enable(
                this,
                SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
                SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        );
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_details);

        packageName = getIntent().getStringExtra(AppConstants.EXTRA_PACKAGE_NAME);
        if (packageName == null || packageName.isEmpty()) {
            Toast.makeText(this, "No package specified", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        initViews();
        setupEdgeToEdgeInsets();
        loadAppDetails();
    }

    @Override
    public void finish() {
        super.finish();
        overridePendingTransition(R.anim.slide_in_left, R.anim.slide_out_right);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }

    private void setupEdgeToEdgeInsets() {
        View topBar = findViewById(R.id.top_bar_details);
        final int topPadLeft = topBar.getPaddingLeft();
        final int topPadTop = topBar.getPaddingTop();
        final int topPadRight = topBar.getPaddingRight();
        final int topPadBottom = topBar.getPaddingBottom();

        ViewCompat.setOnApplyWindowInsetsListener(topBar, (v, insets) -> {
            Insets sysBars = insets.getInsets(WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            v.setPadding(topPadLeft + sysBars.left, topPadTop + sysBars.top, topPadRight + sysBars.right, topPadBottom);
            return insets;
        });

        ScrollView scrollDetails = findViewById(R.id.scroll_app_details);
        final int scrollPadLeft = scrollDetails.getPaddingLeft();
        final int scrollPadTop = scrollDetails.getPaddingTop();
        final int scrollPadRight = scrollDetails.getPaddingRight();
        final int scrollPadBottom = scrollDetails.getPaddingBottom();

        ViewCompat.setOnApplyWindowInsetsListener(scrollDetails, (v, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            v.setPadding(scrollPadLeft + bars.left, scrollPadTop, scrollPadRight + bars.right, scrollPadBottom + bars.bottom);
            return insets;
        });
    }

    private boolean isUiAlive() {
        return !isFinishing() && !isDestroyed();
    }

    private void initViews() {
        ImageButton btnBack = findViewById(R.id.btn_back_details);
        btnBack.setOnClickListener(v -> finish());

        ivDetailIcon = findViewById(R.id.iv_detail_icon);
        tvDetailTitle = findViewById(R.id.tv_detail_title);
        tvDetailSubtitle = findViewById(R.id.tv_detail_subtitle);

        // Overview
        tvOvPackage = findViewById(R.id.tv_ov_package);
        tvOvVersionName = findViewById(R.id.tv_ov_version_name);
        tvOvVersionCode = findViewById(R.id.tv_ov_version_code);
        tvOvSize = findViewById(R.id.tv_ov_size);
        tvOvInstaller = findViewById(R.id.tv_ov_installer);
        tvOvFirstInstalled = findViewById(R.id.tv_ov_first_installed);
        tvOvLastUpdated = findViewById(R.id.tv_ov_last_updated);
        tvOvApkLocation = findViewById(R.id.tv_ov_apk_location);

        btnLaunch = findViewById(R.id.btn_launch_app);
        btnSettings = findViewById(R.id.btn_open_settings);
        btnExport = findViewById(R.id.btn_export_apk);

        // Certificate container
        layoutCertContainer = findViewById(R.id.layout_cert_container);

        // SDK & Perms
        tvMinSdk = findViewById(R.id.tv_min_sdk);
        tvTargetSdk = findViewById(R.id.tv_target_sdk);
        tvCompileSdk = findViewById(R.id.tv_compile_sdk);
        tvPermissionsHeader = findViewById(R.id.tv_permissions_header);
        layoutPermissionsList = findViewById(R.id.layout_permissions_list);

        // Components
        layoutComponentsContainer = findViewById(R.id.layout_components_container);
    }

    private void loadAppDetails() {
        executor.execute(() -> {
            try {
                PackageManager pm = getPackageManager();
                PackageInfo pi = pm.getPackageInfo(packageName, 0);
                ApplicationInfo ai = pi.applicationInfo;

                CharSequence appName = ai != null ? pm.getApplicationLabel(ai) : packageName;
                apkSourceDir = ai != null ? ai.sourceDir : null;

                long size = 0;
                if (apkSourceDir != null) {
                    File apkFile = new File(apkSourceDir);
                    if (apkFile.exists()) size = apkFile.length();
                }
                final long appSize = size;

                long vCode;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    vCode = pi.getLongVersionCode();
                } else {
                    @SuppressWarnings("deprecation")
                    long c = pi.versionCode;
                    vCode = c;
                }

                String installer = "Direct Install";
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        String inst = pm.getInstallSourceInfo(packageName).getInstallingPackageName();
                        if (inst != null) installer = inst;
                    } else {
                        @SuppressWarnings("deprecation")
                        String inst = pm.getInstallerPackageName(packageName);
                        if (inst != null) installer = inst;
                    }
                } catch (Exception ignored) {}

                // Certificates
                CertificateInspector.CertResult certResult = CertificateInspector.inspect(this, packageName);

                // Manifest Components and Permissions
                ManifestInspector.ManifestDetails manifestDetails = ManifestInspector.inspect(this, packageName);

                final String finalInstaller = installer;
                final long finalVCode = vCode;

                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    // Title Header
                    tvDetailTitle.setText(appName);
                    tvDetailSubtitle.setText(packageName);
                    if (ai != null) {
                        ivDetailIcon.setImageDrawable(ai.loadIcon(pm));
                    }

                    // SECTION 1: OVERVIEW METRICS
                    tvOvPackage.setText(packageName);
                    tvOvVersionName.setText(pi.versionName != null ? pi.versionName : "N/A");
                    tvOvVersionCode.setText(String.valueOf(finalVCode));
                    tvOvSize.setText(AppUtils.formatFileSize(appSize));
                    tvOvInstaller.setText(finalInstaller);
                    tvOvFirstInstalled.setText(AppUtils.formatDate(pi.firstInstallTime));
                    tvOvLastUpdated.setText(AppUtils.formatDate(pi.lastUpdateTime));
                    tvOvApkLocation.setText(apkSourceDir != null ? apkSourceDir : "N/A");

                    // Actions
                    Intent launchIntent = pm.getLaunchIntentForPackage(packageName);
                    if (launchIntent != null) {
                        btnLaunch.setEnabled(true);
                        btnLaunch.setOnClickListener(v -> {
                            v.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
                            try {
                                startActivity(launchIntent);
                            } catch (Exception ex) {
                                Toast.makeText(AppDetailsActivity.this, "Cannot launch app: " + ex.getMessage(), Toast.LENGTH_SHORT).show();
                            }
                        });
                    } else {
                        btnLaunch.setEnabled(false);
                    }

                    btnSettings.setOnClickListener(v -> {
                        v.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
                        Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                        intent.setData(Uri.parse("package:" + packageName));
                        try {
                            startActivity(intent);
                        } catch (Exception ex) {
                            Toast.makeText(AppDetailsActivity.this, "Cannot open app settings: " + ex.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });

                    btnExport.setOnClickListener(v -> {
                        v.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
                        showExportOptionsDialog(appName.toString());
                    });

                    // SECTION 2: CERTIFICATES
                    renderCertificates(certResult);

                    // SECTION 3: SDK & PERMISSIONS
                    if (ai != null) {
                        tvTargetSdk.setText("API " + ai.targetSdkVersion);
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                            tvMinSdk.setText("API " + ai.minSdkVersion);
                        } else {
                            tvMinSdk.setText("API 23");
                        }
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                            tvCompileSdk.setText("API " + ai.compileSdkVersion);
                        } else {
                            tvCompileSdk.setText("N/A");
                        }
                    }
                    renderPermissions(manifestDetails);

                    // SECTION 4: COMPONENTS
                    renderComponents(manifestDetails);
                });

            } catch (PackageManager.NameNotFoundException e) {
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    Toast.makeText(AppDetailsActivity.this, "Package is no longer installed: " + packageName, Toast.LENGTH_LONG).show();
                    finish();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    Toast.makeText(AppDetailsActivity.this, "Error loading details: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void showExportOptionsDialog(String appName) {
        if (apkSourceDir == null) {
            Toast.makeText(this, "APK path is unavailable", Toast.LENGTH_SHORT).show();
            return;
        }

        File srcApk = new File(apkSourceDir);
        if (!srcApk.exists()) {
            Toast.makeText(this, "APK source file not found", Toast.LENGTH_SHORT).show();
            return;
        }

        String suggestedName = appName.replaceAll("[^a-zA-Z0-9.-]", "_") + "_" + packageName + ".apk";
        String[] options = {"Save APK to Chosen Folder", "Share APK File"};
        new AlertDialog.Builder(this)
                .setTitle("Export APK")
                .setItems(options, (dialog, which) -> {
                    if (which == 0) {
                        pendingApkToSave = srcApk;
                        saveApkLauncher.launch(suggestedName);
                    } else {
                        shareApkFile(srcApk, suggestedName);
                    }
                })
                .show();
    }

    private void shareApkFile(File srcApk, String cleanName) {
        executor.execute(() -> {
            try {
                File exportsDir = FileManager.getExportsDir(this);
                File destFile = new File(exportsDir, cleanName);
                FileManager.copyFile(srcApk, destFile);
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    Toast.makeText(this, "APK ready: " + destFile.getName(), Toast.LENGTH_SHORT).show();
                    FileManager.shareFile(this, destFile, "application/vnd.android.package-archive");
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    Toast.makeText(this, "Export failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                });
            }
        });
    }

    private void renderCertificates(CertificateInspector.CertResult certResult) {
        layoutCertContainer.removeAllViews();
        LayoutInflater inflater = LayoutInflater.from(this);

        if (certResult.activeCertificates.isEmpty()) {
            TextView tvEmpty = new TextView(this);
            tvEmpty.setText(certResult.errorMessage != null ? certResult.errorMessage : getString(R.string.no_cert_found));
            tvEmpty.setTextColor(ContextCompat.getColor(this, R.color.secondary));
            tvEmpty.setPadding(16, 32, 16, 32);
            layoutCertContainer.addView(tvEmpty);
            return;
        }

        // Active certificates
        for (CertificateInspector.CertInfo cert : certResult.activeCertificates) {
            View card = inflater.inflate(R.layout.item_certificate_card, layoutCertContainer, false);
            bindCertCard(card, cert, false);
            layoutCertContainer.addView(card);
        }

        // Historical certificates
        for (CertificateInspector.CertInfo cert : certResult.historyCertificates) {
            View card = inflater.inflate(R.layout.item_certificate_card, layoutCertContainer, false);
            bindCertCard(card, cert, true);
            layoutCertContainer.addView(card);
        }
    }

    private void bindCertCard(View card, CertificateInspector.CertInfo cert, boolean isHistory) {
        TextView tvBadge = card.findViewById(R.id.tv_cert_badge);
        if (isHistory) {
            tvBadge.setText("Historical Rotated Certificate");
            tvBadge.setTextColor(ContextCompat.getColor(this, R.color.secondary));
        }

        TextView tvSubject = card.findViewById(R.id.tv_cert_subject);
        TextView tvIssuer = card.findViewById(R.id.tv_cert_issuer);
        TextView tvSerial = card.findViewById(R.id.tv_cert_serial);
        TextView tvAlgo = card.findViewById(R.id.tv_cert_algo);
        TextView tvValidFrom = card.findViewById(R.id.tv_cert_valid_from);
        TextView tvValidTo = card.findViewById(R.id.tv_cert_valid_to);
        TextView tvSha256 = card.findViewById(R.id.tv_cert_sha256);
        TextView tvSha1 = card.findViewById(R.id.tv_cert_sha1);
        TextView tvMd5 = card.findViewById(R.id.tv_cert_md5);

        tvSubject.setText(cert.subject != null ? cert.subject : "N/A");
        tvIssuer.setText(cert.issuer != null ? cert.issuer : "N/A");
        tvSerial.setText(cert.serialNumber != null ? cert.serialNumber : "N/A");
        tvAlgo.setText(cert.signatureAlgorithm != null ? cert.signatureAlgorithm : "N/A");
        tvValidFrom.setText(cert.validFrom != null ? cert.validFrom : "N/A");
        tvValidTo.setText(cert.validTo != null ? cert.validTo : "N/A");
        tvSha256.setText(cert.sha256 != null ? cert.sha256 : "N/A");
        tvSha1.setText(cert.sha1 != null ? cert.sha1 : "N/A");
        tvMd5.setText(cert.md5 != null ? cert.md5 : "N/A");
    }

    private void renderPermissions(ManifestInspector.ManifestDetails details) {
        layoutPermissionsList.removeAllViews();
        tvPermissionsHeader.setText("Requested Permissions (" + details.permissions.size() + ")");
        LayoutInflater inflater = LayoutInflater.from(this);

        if (details.permissions.isEmpty()) {
            TextView tvEmpty = new TextView(this);
            tvEmpty.setText(R.string.no_permissions);
            tvEmpty.setTextColor(ContextCompat.getColor(this, R.color.secondary));
            tvEmpty.setPadding(0, 16, 0, 16);
            layoutPermissionsList.addView(tvEmpty);
            return;
        }

        for (ManifestInspector.PermissionItem perm : details.permissions) {
            View row = inflater.inflate(R.layout.item_permission_row, layoutPermissionsList, false);
            TextView tvName = row.findViewById(R.id.tv_perm_name);
            TextView tvDesc = row.findViewById(R.id.tv_perm_desc);
            TextView tvStatus = row.findViewById(R.id.tv_perm_status);

            tvName.setText(perm.name);
            if (perm.description != null && !perm.description.isEmpty()) {
                tvDesc.setText(perm.description);
                tvDesc.setVisibility(View.VISIBLE);
            }

            if (perm.isGranted) {
                tvStatus.setText(R.string.status_granted);
                tvStatus.setBackgroundResource(R.drawable.badge_granted);
                tvStatus.setTextColor(ContextCompat.getColor(this, R.color.success));
            } else {
                tvStatus.setText(R.string.status_not_granted);
                tvStatus.setBackgroundResource(R.drawable.badge_not_granted);
                tvStatus.setTextColor(ContextCompat.getColor(this, R.color.error));
            }

            layoutPermissionsList.addView(row);
        }
    }

    private void renderComponents(ManifestInspector.ManifestDetails details) {
        layoutComponentsContainer.removeAllViews();
        LayoutInflater inflater = LayoutInflater.from(this);

        addComponentCategory("Activities", details.activities, inflater);
        addComponentCategory("Services", details.services, inflater);
        addComponentCategory("Broadcast Receivers", details.receivers, inflater);
        addComponentCategory("Content Providers", details.providers, inflater);
    }

    private void addComponentCategory(String title, java.util.List<ManifestInspector.ComponentItem> items, LayoutInflater inflater) {
        View section = inflater.inflate(R.layout.item_component_section, layoutComponentsContainer, false);
        TextView tvTitle = section.findViewById(R.id.tv_component_section_title);
        TextView tvCount = section.findViewById(R.id.tv_component_count_badge);
        LinearLayout itemsContainer = section.findViewById(R.id.layout_component_items);

        tvTitle.setText(title);
        tvCount.setText(String.valueOf(items.size()));

        if (items.isEmpty()) {
            TextView tvEmpty = new TextView(this);
            tvEmpty.setText("None declared");
            tvEmpty.setTextColor(ContextCompat.getColor(this, R.color.secondary));
            tvEmpty.setTextSize(12);
            tvEmpty.setPadding(0, 4, 0, 4);
            itemsContainer.addView(tvEmpty);
        } else {
            for (ManifestInspector.ComponentItem comp : items) {
                View compRow = inflater.inflate(R.layout.item_component_item, itemsContainer, false);
                TextView tvName = compRow.findViewById(R.id.tv_component_item_name);
                TextView tvBadge = compRow.findViewById(R.id.tv_component_exported_badge);

                tvName.setText(comp.name);
                if (comp.isExported) {
                    tvBadge.setText("Exported");
                    tvBadge.setTextColor(ContextCompat.getColor(this, R.color.primary));
                    tvBadge.setBackgroundResource(R.drawable.badge_bg);
                } else {
                    tvBadge.setText("Internal");
                    tvBadge.setTextColor(ContextCompat.getColor(this, R.color.secondary));
                    tvBadge.setBackgroundResource(R.drawable.bg_mono_block);
                }
                itemsContainer.addView(compRow);
            }
        }

        layoutComponentsContainer.addView(section);
    }
}
