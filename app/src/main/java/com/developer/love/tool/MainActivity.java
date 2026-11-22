package com.developer.love.tool;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.HapticFeedbackConstants;
import android.view.LayoutInflater;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.view.inputmethod.InputMethodManager;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.SystemBarStyle;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.developer.love.tool.conversion.AabSigner;
import com.developer.love.tool.conversion.AabValidator;
import com.developer.love.tool.conversion.ApkFileManager;
import com.developer.love.tool.conversion.BundleConverter;
import com.developer.love.tool.core.AppConstants;
import com.developer.love.tool.core.AppUtils;
import com.developer.love.tool.history.HistoryManager;
import com.developer.love.tool.installedapps.AppInfoModel;
import com.developer.love.tool.installedapps.InstalledAppsManager;
import com.developer.love.tool.keystore.CertificateGenerator;
import com.developer.love.tool.keystore.KeystoreManager;
import com.developer.love.tool.keystore.KeystoreValidator;
import com.developer.love.tool.storage.FileManager;
import com.developer.love.tool.storage.StorageHelper;
import com.developer.love.tool.ui.AppDetailsActivity;
import com.developer.love.tool.ui.HistoryActivity;
import com.developer.love.tool.ui.InstalledAppsAdapter;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.navigation.NavigationView;

import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final ExecutorService aliasLookupExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private Runnable pendingAliasFetchRunnable = null;
    private volatile int aliasFetchSeq = 0;
    private boolean aliasManuallyEdited = false;
    private boolean settingAliasProgrammatically = false;

    // Drawer and Navigation
    private DrawerLayout drawerLayout;
    private NavigationView navView;
    private View sectionInstalledApps;
    private View sectionKeystoreGen;
    private View sectionApkToAab;
    private BottomNavigationView bottomNav;

    // SECTION 1: Installed Apps Explorer
    private final InstalledAppsManager appsManager = new InstalledAppsManager();
    private InstalledAppsAdapter appsAdapter;
    private final List<AppInfoModel> allInstalledApps = new ArrayList<>();
    private EditText etSearchApps;
    private CheckBox cbFilterUserOnly;
    private ImageButton btnSortApps;
    private ImageButton btnRefreshApps;
    private TextView tvAppsCount;
    private ProgressBar pbAppsLoading;
    private TextView tvAppsEmpty;
    private RecyclerView rvInstalledApps;

    private int currentFilterMode = AppConstants.FILTER_USER_ONLY;
    private int currentSortMode = AppConstants.SORT_RECENT_INSTALLED;

    // SECTION 2: Keystore Generator
    private final KeystoreManager keystoreManager = new KeystoreManager();
    private LinearLayout layoutKsForm;
    private LinearLayout layoutKsSuccess;
    private EditText etKsFilename;
    private EditText etKsPassword;
    private ImageButton btnToggleKsPass;
    private RadioGroup rgKsFormat;
    private RadioButton rbFormatPkcs12;
    private RadioButton rbFormatJks;
    private EditText etKeyAlias;
    private EditText etKeyPassword;
    private ImageButton btnToggleKeyPass;
    private EditText etValidityYears;
    private EditText etCertCn;
    private EditText etCertO;
    private EditText etCertOu;
    private EditText etCertL;
    private EditText etCertSt;
    private EditText etCertC;
    private MaterialButton btnDoGenerateKs;

    // Keystore Result Views
    private TextView tvKsResFilename;
    private TextView tvKsResFormat;
    private TextView tvKsResAlias;
    private TextView tvKsResValidity;
    private TextView tvKsResSha256;
    private TextView tvKsResLocation;
    private MaterialButton btnSaveKs;
    private MaterialButton btnShareKs;
    private MaterialButton btnCreateAnotherKs;
    private File lastGeneratedKsFile = null;

    // SECTION 3: APK to AAB + Signing
    private LinearLayout layoutConversionInputs;
    private MaterialButton btnPickApk;
    private TextView tvSelectedApkInfo;
    private MaterialButton btnPickKeystore;
    private TextView tvSelectedKsInfo;
    private EditText etSignKsPass;
    private ImageButton btnToggleSignKsPass;
    private EditText etSignKeyAlias;
    private EditText etSignKeyPass;
    private ImageButton btnToggleSignKeyPass;
    private EditText etOutputBundleName;
    private MaterialButton btnRunConversion;

    // Build console views
    private View cardBuildConsole;
    private ProgressBar pbConsoleSpinner;
    private TextView tvConsoleStatus;
    private LinearLayout layoutConsoleSteps;
    private MaterialButton btnRetryConversion;

    // Conversion result views
    private LinearLayout layoutConversionResult;
    private TextView tvConvOutputName;
    private TextView tvConvSize;
    private TextView tvConvSigningStatus;
    private TextView tvConvKeyInfo;
    private TextView tvConvSha256;
    private TextView tvConvPath;
    private MaterialButton btnSaveConverted;
    private MaterialButton btnShareConverted;
    private MaterialButton btnConvertAnother;
    private MaterialButton btnViewTechNotes;

    private String lastTechnicalReport = "";
    private File selectedApkFile = null;
    private File selectedKeystoreFile = null;
    private String selectedKeystoreBaseInfo = "";
    private File finalSignedBundleFile = null;
    private File pendingSaveFile = null;

    // File pickers
    private final ActivityResultLauncher<Intent> apkPickerLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                    Uri uri = result.getData().getData();
                    if (uri != null) {
                        handlePickedApkUri(uri);
                    }
                }
            }
    );

    private final ActivityResultLauncher<Intent> keystorePickerLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                    Uri uri = result.getData().getData();
                    if (uri != null) {
                        handlePickedKeystoreUri(uri);
                    }
                }
            }
    );

    private final ActivityResultLauncher<String> saveFileToFolderLauncher = registerForActivityResult(
            new ActivityResultContracts.CreateDocument("*/*"),
            uri -> {
                if (uri != null && pendingSaveFile != null) {
                    savePendingFileToUri(uri);
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
        setContentView(R.layout.activity_main);

        initViews();
        setupEdgeToEdgeInsets();
        setupDrawer();
        setupNavigation();
        setupPasswordToggles();
        setupInstalledAppsModule();
        setupKeystoreModule();
        setupConversionModule();

        // Handle back press to close drawer if open
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (drawerLayout != null && drawerLayout.isDrawerOpen(GravityCompat.START)) {
                    drawerLayout.closeDrawer(GravityCompat.START);
                } else {
                    setEnabled(false);
                    getOnBackPressedDispatcher().onBackPressed();
                }
            }
        });

        // Show already-loaded cached apps immediately without repetitive reload spinners
        initInstalledApps();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mainHandler.removeCallbacksAndMessages(null);
        executor.shutdownNow();
        aliasLookupExecutor.shutdownNow();
        appsManager.shutdown();
        keystoreManager.shutdown();
        FileManager.clearTempDir(this);
    }

    private boolean isUiAlive() {
        return !isFinishing() && !isDestroyed();
    }

    private void setupEdgeToEdgeInsets() {
        View topBar = findViewById(R.id.top_app_bar);
        final int topPadLeft = topBar.getPaddingLeft();
        final int topPadTop = topBar.getPaddingTop();
        final int topPadRight = topBar.getPaddingRight();
        final int topPadBottom = topBar.getPaddingBottom();

        ViewCompat.setOnApplyWindowInsetsListener(topBar, (v, insets) -> {
            Insets sysBars = insets.getInsets(WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            v.setPadding(topPadLeft + sysBars.left, topPadTop + sysBars.top, topPadRight + sysBars.right, topPadBottom);
            return insets;
        });

        final int navPadLeft = bottomNav.getPaddingLeft();
        final int navPadTop = bottomNav.getPaddingTop();
        final int navPadRight = bottomNav.getPaddingRight();
        final int navPadBottom = bottomNav.getPaddingBottom();

        final View rootLayout = findViewById(R.id.root_layout);
        final View contentFrame = findViewById(R.id.content_frame);
        final View bottomNavDivider = findViewById(R.id.bottom_nav_divider);

        final Insets[] lastSysBars = {Insets.NONE};
        final Insets[] lastIme = {Insets.NONE};
        final boolean[] lastImeVisible = {false};
        final int[] lastContentHeight = {0};

        final Runnable reconcileBottomInsets = () -> {
            if (!isUiAlive()) return;
            Insets sysBars = lastSysBars[0];
            Insets ime = lastIme[0];
            boolean imeVisible = lastImeVisible[0];

            // Hide bottom navigation & its divider while typing so forms get full vertical space
            int targetNavVis = imeVisible ? View.GONE : View.VISIBLE;
            if (bottomNav.getVisibility() != targetNavVis) {
                bottomNav.setVisibility(targetNavVis);
            }
            if (bottomNavDivider != null && bottomNavDivider.getVisibility() != targetNavVis) {
                bottomNavDivider.setVisibility(targetNavVis);
            }

            bottomNav.setPadding(navPadLeft + sysBars.left, navPadTop, navPadRight + sysBars.right, navPadBottom + sysBars.bottom);

            // Compute actual window overlap below rootLayout so API 24-34 adjustResize does NOT double-pad
            // while API 35-36 enforced EdgeToEdge still pads cleanly above the IME.
            int overlapBottom = 0;
            if (imeVisible) {
                View decorView = getWindow().getDecorView();
                int decorHeight = decorView != null ? decorView.getHeight() : 0;
                int imeBottom = Math.max(ime.bottom, sysBars.bottom);
                if (decorHeight > 0 && rootLayout.getHeight() > 0) {
                    int[] rootLoc = new int[2];
                    rootLayout.getLocationInWindow(rootLoc);
                    int rootBottom = rootLoc[1] + rootLayout.getHeight();
                    int imeTopInWindow = decorHeight - imeBottom;
                    overlapBottom = Math.max(0, rootBottom - imeTopInWindow);
                } else {
                    overlapBottom = imeBottom;
                }
            }

            if (contentFrame.getPaddingLeft() != sysBars.left
                    || contentFrame.getPaddingTop() != 0
                    || contentFrame.getPaddingRight() != sysBars.right
                    || contentFrame.getPaddingBottom() != overlapBottom) {
                contentFrame.setPadding(sysBars.left, 0, sysBars.right, overlapBottom);
            }

            // If a ScrollView shrunk while an EditText inside it holds focus, keep field + label unclipped
            int currentHeight = contentFrame.getHeight();
            boolean shrunk = lastContentHeight[0] > 0 && currentHeight > 0 && currentHeight < lastContentHeight[0];
            if (currentHeight > 0) {
                lastContentHeight[0] = currentHeight;
            }
            if (imeVisible && shrunk) {
                ensureVisibleFormScrollTarget();
            }
        };

        ViewCompat.setOnApplyWindowInsetsListener(rootLayout, (v, insets) -> {
            Insets sysBars = insets.getInsets(WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            Insets ime = insets.getInsets(WindowInsetsCompat.Type.ime());
            boolean wasImeVisible = lastImeVisible[0];
            boolean imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime()) || ime.bottom > sysBars.bottom;

            lastSysBars[0] = sysBars;
            lastIme[0] = ime;
            lastImeVisible[0] = imeVisible;

            reconcileBottomInsets.run();
            if (imeVisible && !wasImeVisible) {
                rootLayout.post(this::ensureVisibleFormScrollTarget);
            }
            return insets;
        });

        rootLayout.addOnLayoutChangeListener((v, left, top, right, bottom, oldLeft, oldTop, oldRight, oldBottom) -> {
            if ((bottom - top) != (oldBottom - oldTop) || lastImeVisible[0]) {
                rootLayout.post(reconcileBottomInsets);
            }
        });
    }

    private void ensureVisibleFormScrollTarget() {
        if (!isUiAlive()) return;
        if (sectionKeystoreGen instanceof ScrollView && sectionKeystoreGen.getVisibility() == View.VISIBLE) {
            ensureFocusedFieldAndLabelVisible((ScrollView) sectionKeystoreGen);
        } else if (sectionApkToAab instanceof ScrollView && sectionApkToAab.getVisibility() == View.VISIBLE) {
            ensureFocusedFieldAndLabelVisible((ScrollView) sectionApkToAab);
        }
    }

    private void ensureFocusedFieldAndLabelVisible(ScrollView scrollView) {
        if (scrollView == null || scrollView.getVisibility() != View.VISIBLE) return;
        View focused = scrollView.findFocus();
        if (!(focused instanceof EditText) || !focused.isShown()) return;

        int[] svLoc = new int[2];
        scrollView.getLocationInWindow(svLoc);
        int visibleTop = svLoc[1] + scrollView.getPaddingTop();
        int visibleBottom = svLoc[1] + scrollView.getHeight() - scrollView.getPaddingBottom();
        int visibleHeight = visibleBottom - visibleTop;
        if (visibleHeight <= 0) return;

        int[] etLoc = new int[2];
        focused.getLocationInWindow(etLoc);
        int etTop = etLoc[1];
        int etBottom = etTop + focused.getHeight();

        float density = getResources().getDisplayMetrics().density;
        int labelHeadroomPx = Math.round(28f * density);
        int bottomMarginPx = Math.round(16f * density);

        if (etTop - labelHeadroomPx < visibleTop) {
            if (visibleHeight >= focused.getHeight() + labelHeadroomPx) {
                int deltaUp = (etTop - labelHeadroomPx) - visibleTop;
                scrollView.smoothScrollBy(0, deltaUp);
            }
        } else if (etBottom + bottomMarginPx > visibleBottom) {
            int neededDown = (etBottom + bottomMarginPx) - visibleBottom;
            int maxDownWithoutClippingLabel = Math.max(0, (etTop - labelHeadroomPx) - visibleTop);
            int deltaDown = Math.min(neededDown, maxDownWithoutClippingLabel);
            if (deltaDown > 0) {
                scrollView.smoothScrollBy(0, deltaDown);
            }
        }
    }

    private void attachFormScrollFocusGuards(ScrollView scrollView, EditText... fields) {
        if (scrollView == null || fields == null) return;
        View.OnFocusChangeListener listener = (v, hasFocus) -> {
            if (hasFocus) {
                scrollView.postDelayed(() -> ensureFocusedFieldAndLabelVisible(scrollView), 80L);
            }
        };
        for (EditText field : fields) {
            if (field != null) {
                field.setOnFocusChangeListener(listener);
            }
        }
    }

    private void animateReveal(View view) {
        if (view == null) return;
        view.animate().cancel();
        view.setAlpha(0f);
        view.setTranslationY(18f);
        view.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(200)
                .setInterpolator(new DecelerateInterpolator())
                .start();
    }

    private void performConfirmHaptic(View view) {
        if (view == null) return;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            view.performHapticFeedback(HapticFeedbackConstants.CONFIRM);
        } else {
            view.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
        }
    }

    private void deleteStaleTempFile(@Nullable File file, File tempDir) {
        if (file != null && tempDir != null) {
            try {
                String canonicalTemp = tempDir.getCanonicalPath();
                String canonicalFile = file.getCanonicalPath();
                if (canonicalFile.startsWith(canonicalTemp + File.separator) && file.exists()) {
                    file.delete();
                }
            } catch (Exception ignored) {}
        }
    }

    private void initViews() {
        drawerLayout = findViewById(R.id.drawer_layout);
        navView = findViewById(R.id.nav_view);

        sectionInstalledApps = findViewById(R.id.section_installed_apps);
        sectionKeystoreGen = findViewById(R.id.section_keystore_gen);
        sectionApkToAab = findViewById(R.id.section_apk_to_aab);
        bottomNav = findViewById(R.id.bottom_navigation);

        // Header buttons
        ImageButton btnMenu = findViewById(R.id.btn_menu);
        btnMenu.setOnClickListener(v -> drawerLayout.openDrawer(GravityCompat.START));

        ImageButton btnHistoryTop = findViewById(R.id.btn_history_top);
        btnHistoryTop.setOnClickListener(v -> openHistoryActivity());

        btnRefreshApps = findViewById(R.id.btn_refresh);
        btnRefreshApps.setOnClickListener(v -> {
            Toast.makeText(this, "Refreshing installed apps…", Toast.LENGTH_SHORT).show();
            loadInstalledApps(allInstalledApps.isEmpty(), true);
        });

        // Section 1: Installed Apps
        etSearchApps = findViewById(R.id.et_search_apps);
        cbFilterUserOnly = findViewById(R.id.cb_filter_user_only);
        btnSortApps = findViewById(R.id.btn_sort_apps);
        tvAppsCount = findViewById(R.id.tv_app_count);
        pbAppsLoading = findViewById(R.id.pb_apps_loading);
        tvAppsEmpty = findViewById(R.id.tv_apps_empty);
        rvInstalledApps = findViewById(R.id.rv_installed_apps);

        // Section 2: Keystore Generator
        layoutKsForm = findViewById(R.id.layout_keystore_form);
        layoutKsSuccess = findViewById(R.id.layout_keystore_success);
        etKsFilename = findViewById(R.id.et_keystore_filename);
        etKsPassword = findViewById(R.id.et_keystore_password);
        btnToggleKsPass = findViewById(R.id.btn_toggle_ks_pass);
        rgKsFormat = findViewById(R.id.rg_keystore_format);
        rbFormatPkcs12 = findViewById(R.id.rb_format_pkcs12);
        rbFormatJks = findViewById(R.id.rb_format_jks);
        etKeyAlias = findViewById(R.id.et_key_alias);
        etKeyPassword = findViewById(R.id.et_key_password);
        btnToggleKeyPass = findViewById(R.id.btn_toggle_key_pass);
        etValidityYears = findViewById(R.id.et_validity_years);
        etCertCn = findViewById(R.id.et_cert_cn);
        etCertO = findViewById(R.id.et_cert_o);
        etCertOu = findViewById(R.id.et_cert_ou);
        etCertL = findViewById(R.id.et_cert_l);
        etCertSt = findViewById(R.id.et_cert_st);
        etCertC = findViewById(R.id.et_cert_c);
        btnDoGenerateKs = findViewById(R.id.btn_do_generate_keystore);

        tvKsResFilename = findViewById(R.id.tv_ks_res_filename);
        tvKsResFormat = findViewById(R.id.tv_ks_res_format);
        tvKsResAlias = findViewById(R.id.tv_ks_res_alias);
        tvKsResValidity = findViewById(R.id.tv_ks_res_validity);
        tvKsResSha256 = findViewById(R.id.tv_ks_res_sha256);
        tvKsResLocation = findViewById(R.id.tv_ks_res_location);
        btnSaveKs = findViewById(R.id.btn_save_keystore);
        btnShareKs = findViewById(R.id.btn_share_keystore);
        btnCreateAnotherKs = findViewById(R.id.btn_create_another_ks);

        // Section 3: APK to AAB
        layoutConversionInputs = findViewById(R.id.layout_conversion_inputs);
        btnPickApk = findViewById(R.id.btn_pick_apk);
        tvSelectedApkInfo = findViewById(R.id.tv_selected_apk_info);
        btnPickKeystore = findViewById(R.id.btn_pick_keystore);
        tvSelectedKsInfo = findViewById(R.id.tv_selected_ks_info);
        etSignKsPass = findViewById(R.id.et_sign_ks_pass);
        btnToggleSignKsPass = findViewById(R.id.btn_toggle_sign_ks_pass);
        etSignKeyAlias = findViewById(R.id.et_sign_key_alias);
        etSignKeyPass = findViewById(R.id.et_sign_key_pass);
        btnToggleSignKeyPass = findViewById(R.id.btn_toggle_sign_key_pass);
        etOutputBundleName = findViewById(R.id.et_output_bundle_name);
        btnRunConversion = findViewById(R.id.btn_run_conversion);

        // Build console views
        cardBuildConsole = findViewById(R.id.card_build_console);
        pbConsoleSpinner = findViewById(R.id.pb_console_spinner);
        tvConsoleStatus = findViewById(R.id.tv_console_status);
        layoutConsoleSteps = findViewById(R.id.layout_console_steps);
        btnRetryConversion = findViewById(R.id.btn_retry_conversion);

        // Conversion result views
        layoutConversionResult = findViewById(R.id.layout_conversion_result);
        tvConvOutputName = findViewById(R.id.tv_conv_output_name);
        tvConvSize = findViewById(R.id.tv_conv_size);
        tvConvSigningStatus = findViewById(R.id.tv_conv_signing_status);
        tvConvKeyInfo = findViewById(R.id.tv_conv_key_info);
        tvConvSha256 = findViewById(R.id.tv_conv_sha256);
        tvConvPath = findViewById(R.id.tv_conv_path);
        btnSaveConverted = findViewById(R.id.btn_save_converted);
        btnShareConverted = findViewById(R.id.btn_share_converted);
        btnConvertAnother = findViewById(R.id.btn_convert_another);
        btnViewTechNotes = findViewById(R.id.btn_view_tech_notes);
    }

    private void setupPasswordToggles() {
        attachPasswordToggle(etKsPassword, btnToggleKsPass);
        attachPasswordToggle(etKeyPassword, btnToggleKeyPass);
        attachPasswordToggle(etSignKsPass, btnToggleSignKsPass);
        attachPasswordToggle(etSignKeyPass, btnToggleSignKeyPass);
    }

    private void attachPasswordToggle(EditText editText, ImageButton toggleBtn) {
        if (editText == null || toggleBtn == null) return;
        toggleBtn.setOnClickListener(v -> {
            int selectionStart = editText.getSelectionStart();
            int selectionEnd = editText.getSelectionEnd();
            boolean isCurrentlyHidden = editText.getTransformationMethod() instanceof PasswordTransformationMethod;

            if (isCurrentlyHidden) {
                editText.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                toggleBtn.setImageResource(R.drawable.ic_visibility);
            } else {
                editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
                toggleBtn.setImageResource(R.drawable.ic_visibility_off);
            }

            if (selectionStart >= 0 && selectionEnd >= 0) {
                editText.setSelection(selectionStart, selectionEnd);
            }
        });
    }

    private void setupDrawer() {
        navView.setNavigationItemSelectedListener(item -> {
            drawerLayout.closeDrawer(GravityCompat.START);
            int id = item.getItemId();
            if (id == R.id.nav_history) {
                openHistoryActivity();
            } else if (id == R.id.nav_how_to_use) {
                showHowToUseDialog();
            } else if (id == R.id.nav_privacy_policy) {
                showPrivacyPolicyDialog();
            } else if (id == R.id.nav_rating) {
                showRatingDialog();
            } else if (id == R.id.nav_report) {
                showReportDialog();
            } else if (id == R.id.nav_join) {
                showJoinCommunityDialog();
            } else if (id == R.id.nav_contact) {
                showDeveloperContactDialog();
            }
            return true;
        });
    }

    private void openHistoryActivity() {
        startActivity(new Intent(this, HistoryActivity.class));
        overridePendingTransition(R.anim.slide_in_right, R.anim.slide_out_left);
    }

    private void setupNavigation() {
        bottomNav.setOnItemSelectedListener(item -> {
            bottomNav.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
            int id = item.getItemId();
            if (id == R.id.action_installed_apps) {
                showSection(sectionInstalledApps);
                return true;
            } else if (id == R.id.action_keystore_gen) {
                showSection(sectionKeystoreGen);
                return true;
            } else if (id == R.id.action_apk_to_aab) {
                showSection(sectionApkToAab);
                return true;
            }
            return false;
        });
    }

    private void showSection(View targetSection) {
        boolean alreadyVisible = targetSection.getVisibility() == View.VISIBLE;
        if (!alreadyVisible) {
            View currentFocus = getCurrentFocus();
            if (currentFocus instanceof EditText) {
                currentFocus.clearFocus();
                InputMethodManager imm = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
                if (imm != null) {
                    imm.hideSoftInputFromWindow(currentFocus.getWindowToken(), 0);
                }
            }
        }
        sectionInstalledApps.setVisibility(targetSection == sectionInstalledApps ? View.VISIBLE : View.GONE);
        sectionKeystoreGen.setVisibility(targetSection == sectionKeystoreGen ? View.VISIBLE : View.GONE);
        sectionApkToAab.setVisibility(targetSection == sectionApkToAab ? View.VISIBLE : View.GONE);
        if (!alreadyVisible) {
            animateReveal(targetSection);
        }
    }

    private void launchSaveToFolder(File sourceFile) {
        if (sourceFile == null || !sourceFile.exists()) {
            Toast.makeText(this, "File not available on disk.", Toast.LENGTH_SHORT).show();
            return;
        }
        pendingSaveFile = sourceFile;
        saveFileToFolderLauncher.launch(sourceFile.getName());
    }

    private void savePendingFileToUri(Uri destUri) {
        final File source = pendingSaveFile;
        pendingSaveFile = null;
        if (source == null || !source.exists()) return;

        executor.execute(() -> {
            try {
                FileManager.copyFileToUri(this, source, destUri);
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    Toast.makeText(this, "Saved '" + source.getName() + "' to selected folder!", Toast.LENGTH_LONG).show();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    Toast.makeText(this, "Save failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    // ==========================================
    // MODULE 1: INSTALLED APPS EXPLORER
    // ==========================================
    private void setupInstalledAppsModule() {
        rvInstalledApps.setLayoutManager(new LinearLayoutManager(this));
        appsAdapter = new InstalledAppsAdapter(this, app -> {
            Intent intent = new Intent(this, AppDetailsActivity.class);
            intent.putExtra(AppConstants.EXTRA_PACKAGE_NAME, app.getPackageName());
            startActivity(intent);
            overridePendingTransition(R.anim.slide_in_right, R.anim.slide_out_left);
        });
        rvInstalledApps.setAdapter(appsAdapter);

        etSearchApps.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                applyAppsFilterAndSort();
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        cbFilterUserOnly.setOnCheckedChangeListener((buttonView, isChecked) -> {
            currentFilterMode = isChecked ? AppConstants.FILTER_USER_ONLY : AppConstants.FILTER_ALL;
            applyAppsFilterAndSort();
        });

        btnSortApps.setOnClickListener(v -> showSortDialog());
    }

    private void initInstalledApps() {
        List<AppInfoModel> cached = InstalledAppsManager.getCachedApps(this);
        if (!cached.isEmpty()) {
            allInstalledApps.clear();
            allInstalledApps.addAll(cached);
            pbAppsLoading.setVisibility(View.GONE);
            applyAppsFilterAndSort();

            // Quietly sync in background once per app process launch without showing a spinner
            if (!InstalledAppsManager.hasScannedThisSession()) {
                loadInstalledApps(false, false);
            }
        } else {
            loadInstalledApps(true, false);
        }
    }

    private void loadInstalledApps(boolean showCenterSpinner, boolean notifyUserOnComplete) {
        if (showCenterSpinner && allInstalledApps.isEmpty()) {
            pbAppsLoading.setVisibility(View.VISIBLE);
            tvAppsEmpty.setVisibility(View.GONE);
        } else {
            pbAppsLoading.setVisibility(View.GONE);
        }

        appsManager.loadAppsAsync(this, new InstalledAppsManager.OnAppsLoadedListener() {
            @Override
            public void onAppsLoaded(List<AppInfoModel> apps) {
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    allInstalledApps.clear();
                    if (apps != null) {
                        allInstalledApps.addAll(apps);
                    }
                    pbAppsLoading.setVisibility(View.GONE);
                    applyAppsFilterAndSort();
                    if (notifyUserOnComplete) {
                        Toast.makeText(MainActivity.this, "App list updated (" + allInstalledApps.size() + " packages)", Toast.LENGTH_SHORT).show();
                    }
                });
            }

            @Override
            public void onError(String message) {
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    pbAppsLoading.setVisibility(View.GONE);
                    Toast.makeText(MainActivity.this, "Failed to load apps: " + message, Toast.LENGTH_SHORT).show();
                    applyAppsFilterAndSort();
                });
            }
        });
    }

    private void applyAppsFilterAndSort() {
        String query = etSearchApps.getText().toString();
        List<AppInfoModel> filtered = InstalledAppsManager.filterAndSort(allInstalledApps, query, currentFilterMode, currentSortMode);

        appsAdapter.updateList(filtered);
        tvAppsCount.setText(filtered.size() + " Apps");
        tvAppsEmpty.setVisibility(filtered.isEmpty() ? View.VISIBLE : View.GONE);
    }

    private void showSortDialog() {
        String[] options = {
                getString(R.string.sort_recent_installed),
                getString(R.string.sort_alpha_asc),
                getString(R.string.sort_alpha_desc),
                getString(R.string.sort_size_desc)
        };

        new AlertDialog.Builder(this)
                .setTitle(R.string.action_sort)
                .setItems(options, (dialog, which) -> {
                    switch (which) {
                        case 0:
                            currentSortMode = AppConstants.SORT_RECENT_INSTALLED;
                            break;
                        case 1:
                            currentSortMode = AppConstants.SORT_ALPHA_ASC;
                            break;
                        case 2:
                            currentSortMode = AppConstants.SORT_ALPHA_DESC;
                            break;
                        case 3:
                            currentSortMode = AppConstants.SORT_SIZE_DESC;
                            break;
                    }
                    applyAppsFilterAndSort();
                })
                .show();
    }

    // ==========================================
    // MODULE 2: KEYSTORE GENERATOR
    // ==========================================
    private void setupKeystoreModule() {
        btnDoGenerateKs.setOnClickListener(v -> generateKeystore());

        btnSaveKs.setOnClickListener(v -> launchSaveToFolder(lastGeneratedKsFile));

        btnShareKs.setOnClickListener(v -> {
            if (lastGeneratedKsFile != null && lastGeneratedKsFile.exists()) {
                FileManager.shareFile(this, lastGeneratedKsFile, "application/octet-stream");
            }
        });

        btnCreateAnotherKs.setOnClickListener(v -> {
            layoutKsSuccess.setVisibility(View.GONE);
            layoutKsForm.setVisibility(View.VISIBLE);
            etKsFilename.setText("");
            etKsPassword.setText("");
            etKeyPassword.setText("");
            etValidityYears.setText("100");
        });

        if (sectionKeystoreGen instanceof ScrollView) {
            attachFormScrollFocusGuards(
                    (ScrollView) sectionKeystoreGen,
                    etKsFilename, etKsPassword, etKeyAlias, etKeyPassword, etValidityYears,
                    etCertC, etCertCn, etCertO, etCertOu, etCertL, etCertSt
            );
        }
    }

    private void generateKeystore() {
        String filename = etKsFilename.getText().toString();
        String ksPassword = etKsPassword.getText().toString();
        String format = rbFormatPkcs12.isChecked() ? AppConstants.FORMAT_PKCS12 : AppConstants.FORMAT_JKS;
        String alias = etKeyAlias.getText().toString();
        String keyPassword = etKeyPassword.getText().toString();
        String validityStr = etValidityYears.getText().toString();
        String cn = etCertCn.getText().toString();
        String o = etCertO.getText().toString();
        String ou = etCertOu.getText().toString();
        String l = etCertL.getText().toString();
        String st = etCertSt.getText().toString();
        String c = etCertC.getText().toString();

        KeystoreValidator.ValidationResult val = KeystoreValidator.validate(
                filename, ksPassword, alias, keyPassword, validityStr, cn, o, c
        );

        if (!val.isValid) {
            Toast.makeText(this, val.errorMessage, Toast.LENGTH_LONG).show();
            return;
        }

        int validityYears = Integer.parseInt(validityStr.trim());

        String cleanName = filename.trim();
        String ext = format.equalsIgnoreCase(AppConstants.FORMAT_JKS) ? ".jks" : ".p12";
        if (!cleanName.toLowerCase().endsWith(".jks")
                && !cleanName.toLowerCase().endsWith(".p12")
                && !cleanName.toLowerCase().endsWith(".keystore")) {
            cleanName = cleanName + ext;
        }

        File destFile = new File(FileManager.getKeystoresDir(this), cleanName);

        final String finalCleanName = cleanName;
        if (destFile.exists()) {
            new AlertDialog.Builder(this)
                    .setTitle(R.string.title_confirm_overwrite)
                    .setMessage(R.string.msg_confirm_overwrite)
                    .setPositiveButton(R.string.btn_overwrite, (d, w) -> proceedKeystoreGeneration(
                            finalCleanName, ksPassword, format, alias, keyPassword, validityYears, cn, o, ou, l, st, c
                    ))
                    .setNegativeButton(android.R.string.cancel, null)
                    .show();
        } else {
            proceedKeystoreGeneration(
                    finalCleanName, ksPassword, format, alias, keyPassword, validityYears, cn, o, ou, l, st, c
            );
        }
    }

    private void proceedKeystoreGeneration(
            String filename, String ksPassword, String format, String alias, String keyPassword,
            int validityYears, String cn, String o, String ou, String l, String st, String c
    ) {
        Toast.makeText(this, "Generating cryptographic keypair...", Toast.LENGTH_SHORT).show();

        CertificateGenerator.CertParams certParams = new CertificateGenerator.CertParams();
        certParams.commonName = cn;
        certParams.organization = o;
        certParams.organizationalUnit = ou;
        certParams.locality = l;
        certParams.state = st;
        certParams.countryCode = c;
        certParams.validityYears = validityYears;

        keystoreManager.generateKeystoreAsync(
                this, filename, ksPassword, alias, keyPassword, certParams, format,
                result -> runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    // Clear sensitive passwords immediately from memory
                    etKsPassword.setText("");
                    etKeyPassword.setText("");

                    if (result.isSuccess) {
                        lastGeneratedKsFile = new File(result.filePath);

                        tvKsResFilename.setText(result.fileName);
                        tvKsResFormat.setText(result.format);
                        tvKsResAlias.setText(result.alias);
                        tvKsResValidity.setText(result.validityYears + (result.validityYears == 1 ? " Year" : " Years"));
                        tvKsResSha256.setText(result.sha256);
                        tvKsResLocation.setText(result.filePath);

                        layoutKsForm.setVisibility(View.GONE);
                        layoutKsSuccess.setVisibility(View.VISIBLE);
                        animateReveal(layoutKsSuccess);
                        performConfirmHaptic(layoutKsSuccess);

                        // Save to persistent history
                        HistoryManager.saveKeystoreRecord(MainActivity.this, new HistoryManager.KeystoreRecord(
                                result.fileName,
                                result.format,
                                result.alias,
                                result.validityYears,
                                result.sha256,
                                result.filePath,
                                System.currentTimeMillis()
                        ));

                        Toast.makeText(MainActivity.this, "Keystore created & verified!", Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(MainActivity.this, result.errorMessage, Toast.LENGTH_LONG).show();
                    }
                })
        );
    }

    // ==========================================
    // MODULE 3: APK TO AAB + SIGNING
    // ==========================================
    private void setupConversionModule() {
        btnPickApk.setOnClickListener(v -> showApkSelectionOptions());
        btnPickKeystore.setOnClickListener(v -> showKeystoreSelectionDialog());
        btnRunConversion.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
            runApkToAabProcess();
        });

        findViewById(R.id.btn_auto_fetch_alias).setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
            aliasManuallyEdited = false;
            autoFetchAliasFromKeystore(true, false);
        });

        etSignKeyAlias.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (!settingAliasProgrammatically) {
                    aliasManuallyEdited = s.toString().trim().length() > 0;
                }
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        etSignKsPass.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (pendingAliasFetchRunnable != null) {
                    mainHandler.removeCallbacks(pendingAliasFetchRunnable);
                }
                if (selectedKeystoreFile != null && s.length() >= 1) {
                    final boolean shouldFill = !aliasManuallyEdited || etSignKeyAlias.getText().toString().trim().isEmpty();
                    if (shouldFill) {
                        pendingAliasFetchRunnable = () -> autoFetchAliasFromKeystore(false, true);
                        mainHandler.postDelayed(pendingAliasFetchRunnable, 250);
                    }
                }
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        btnRetryConversion.setOnClickListener(v -> {
            cardBuildConsole.setVisibility(View.GONE);
            layoutConversionInputs.setVisibility(View.VISIBLE);
            btnRunConversion.setEnabled(true);
            btnRunConversion.setText(R.string.btn_start_conversion);
        });

        btnConvertAnother.setOnClickListener(v -> {
            layoutConversionResult.setVisibility(View.GONE);
            cardBuildConsole.setVisibility(View.GONE);
            layoutConversionInputs.setVisibility(View.VISIBLE);
            btnRunConversion.setEnabled(true);
            btnRunConversion.setText(R.string.btn_start_conversion);
        });

        btnViewTechNotes.setOnClickListener(v -> {
            if (!lastTechnicalReport.isEmpty()) {
                new AlertDialog.Builder(this)
                        .setTitle("Technical Architecture Notes")
                        .setMessage(lastTechnicalReport)
                        .setPositiveButton("Close", null)
                        .show();
            }
        });

        btnSaveConverted.setOnClickListener(v -> launchSaveToFolder(finalSignedBundleFile));

        btnShareConverted.setOnClickListener(v -> {
            if (finalSignedBundleFile != null && finalSignedBundleFile.exists()) {
                FileManager.shareFile(this, finalSignedBundleFile, "application/octet-stream");
            }
        });

        if (sectionApkToAab instanceof ScrollView) {
            attachFormScrollFocusGuards(
                    (ScrollView) sectionApkToAab,
                    etSignKsPass, etSignKeyAlias, etSignKeyPass, etOutputBundleName
            );
        }
    }

    private void showApkSelectionOptions() {
        if (allInstalledApps.isEmpty()) {
            launchSystemApkPicker();
            return;
        }

        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_searchable_app_picker, null);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(dialogView)
                .create();

        EditText etSearch = dialogView.findViewById(R.id.et_picker_search);
        TextView tvCount = dialogView.findViewById(R.id.tv_picker_count);
        RecyclerView rvPicker = dialogView.findViewById(R.id.rv_picker_apps);
        MaterialButton btnBrowseStorage = dialogView.findViewById(R.id.btn_picker_browse_storage);

        rvPicker.setLayoutManager(new LinearLayoutManager(this));

        List<AppInfoModel> userApps = InstalledAppsManager.filterAndSort(
                allInstalledApps,
                "",
                AppConstants.FILTER_USER_ONLY,
                AppConstants.SORT_RECENT_INSTALLED
        );
        tvCount.setText(userApps.size() + " Apps");

        InstalledAppsAdapter pickerAdapter = new InstalledAppsAdapter(this, true, selectedApp -> {
            dialog.dismiss();
            try {
                android.content.pm.ApplicationInfo ai = getPackageManager().getApplicationInfo(selectedApp.getPackageName(), 0);
                String sourceDir = ai.sourceDir;
                if (sourceDir != null) {
                    File candidateApk = new File(sourceDir);
                    boolean isSplitApp = ai.splitSourceDirs != null && ai.splitSourceDirs.length > 0;
                    if (isSplitApp) {
                        new AlertDialog.Builder(this)
                                .setTitle("Split APK Warning (" + selectedApp.getAppName() + ")")
                                .setMessage("This installed app uses Split APKs (" + (ai.splitSourceDirs.length + 1) + " files). Converting only base.apk will omit split drawables, native ABIs, or locale strings and may fail Play Store validation or lose UI features.\n\nRecommended: select a standalone/universal .apk from storage.")
                                .setPositiveButton("Browse Storage (.apk)", (d, w) -> launchSystemApkPicker())
                                .setNeutralButton("Use base.apk Anyway", (d, w) -> applySelectedInstalledApk(selectedApp, candidateApk, true))
                                .setNegativeButton(android.R.string.cancel, null)
                                .show();
                    } else {
                        applySelectedInstalledApk(selectedApp, candidateApk, false);
                    }
                }
            } catch (Exception e) {
                Toast.makeText(this, "Failed to read APK: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        });
        pickerAdapter.updateList(userApps);
        rvPicker.setAdapter(pickerAdapter);

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String q = s.toString().toLowerCase(Locale.getDefault()).trim();
                List<AppInfoModel> filtered = new ArrayList<>();
                for (AppInfoModel app : userApps) {
                    if (app.getAppName().toLowerCase(Locale.getDefault()).contains(q) ||
                            app.getPackageName().toLowerCase(Locale.getDefault()).contains(q)) {
                        filtered.add(app);
                    }
                }
                pickerAdapter.updateList(filtered);
                tvCount.setText(filtered.size() + " Apps");
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        btnBrowseStorage.setOnClickListener(v -> {
            dialog.dismiss();
            launchSystemApkPicker();
        });

        dialog.show();
    }

    private void applySelectedInstalledApk(AppInfoModel selectedApp, File candidateApk, boolean isSplitApp) {
        deleteStaleTempFile(selectedApkFile, FileManager.getTempDir(this));
        selectedApkFile = candidateApk;
        String splitNote = isSplitApp ? " (Split base.apk - incomplete for Play Store)" : "";
        tvSelectedApkInfo.setText(selectedApp.getAppName() + " (" + selectedApp.getPackageName() + ") • "
                + AppUtils.formatFileSize(selectedApkFile.length()) + splitNote);
        etOutputBundleName.setText(selectedApp.getPackageName() + "-bundle.aab");
    }

    private void launchSystemApkPicker() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/vnd.android.package-archive");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        try {
            apkPickerLauncher.launch(Intent.createChooser(intent, "Select APK File"));
        } catch (Exception e) {
            Toast.makeText(this, "No file manager found: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void handlePickedApkUri(Uri uri) {
        executor.execute(() -> {
            File tempApk = null;
            try {
                File tempDir = FileManager.getTempDir(this);
                if (!StorageHelper.hasEnoughStorage(tempDir, 20L * 1024L * 1024L)) {
                    throw new IllegalStateException("Insufficient device storage available to stage APK.");
                }
                String pickedName = FileManager.getFileName(this, uri).replaceAll("[^a-zA-Z0-9._-]", "_");
                if (!pickedName.toLowerCase(Locale.US).endsWith(".apk")) pickedName = "selected_input.apk";
                tempApk = new File(tempDir, "apk_" + System.currentTimeMillis() + "_" + pickedName);
                FileManager.copyUriToFile(this, uri, tempApk);

                ApkFileManager.ApkAnalysis analysis = ApkFileManager.analyzeApk(tempApk);
                if (!analysis.isValidApk) {
                    if (tempApk.exists()) tempApk.delete();
                    runOnUiThread(() -> {
                        if (!isUiAlive()) return;
                        Toast.makeText(this, "Invalid APK: " + analysis.errorMessage, Toast.LENGTH_LONG).show();
                    });
                    return;
                }

                deleteStaleTempFile(selectedApkFile, tempDir);
                selectedApkFile = tempApk;
                final File acceptedApk = tempApk;
                final String displayName = pickedName;
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    tvSelectedApkInfo.setText(displayName + " (" + AppUtils.formatFileSize(acceptedApk.length()) + ")");
                    String baseName = displayName.replaceAll("(?i)\\.apk$", "");
                    etOutputBundleName.setText(baseName + "-bundle.aab");
                    Toast.makeText(this, "APK selected successfully!", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                if (tempApk != null && tempApk.exists()) tempApk.delete();
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    Toast.makeText(this, "Failed to load APK: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void showKeystoreSelectionDialog() {
        List<File> generatedKeys = FileManager.listKeystoreFiles(this);
        List<HistoryManager.KeystoreRecord> records = HistoryManager.getKeystoreRecords(this);
        List<String> options = new ArrayList<>();
        List<String> knownAliases = new ArrayList<>();

        for (File f : generatedKeys) {
            String aliasHint = "";
            for (HistoryManager.KeystoreRecord r : records) {
                if (r.fileName != null && r.fileName.equalsIgnoreCase(f.getName())) {
                    aliasHint = r.alias;
                    break;
                }
            }
            if (aliasHint.isEmpty()) {
                List<String> binaryAliases = KeystoreManager.extractAliasesFromJksBinary(f);
                if (!binaryAliases.isEmpty()) {
                    aliasHint = binaryAliases.get(0);
                }
            }
            knownAliases.add(aliasHint);
            if (!aliasHint.isEmpty()) {
                options.add(f.getName() + " (Alias: " + aliasHint + ")");
            } else {
                options.add(f.getName());
            }
        }
        options.add("Browse Device Storage…");

        String[] items = options.toArray(new String[0]);

        new AlertDialog.Builder(this)
                .setTitle("Select Keystore")
                .setItems(items, (dialog, which) -> {
                    if (which < generatedKeys.size()) {
                        deleteStaleTempFile(selectedKeystoreFile, FileManager.getTempDir(this));
                        selectedKeystoreFile = generatedKeys.get(which);
                        selectedKeystoreBaseInfo = selectedKeystoreFile.getName() + " (" + AppUtils.formatFileSize(selectedKeystoreFile.length()) + ")";
                        tvSelectedKsInfo.setText(selectedKeystoreBaseInfo);
                        etSignKsPass.setText("");
                        aliasManuallyEdited = false;
                        setAliasTextProgrammatically("");
                        String fastAlias = knownAliases.get(which);
                        if (!fastAlias.isEmpty()) {
                            setAliasTextProgrammatically(fastAlias);
                            tvSelectedKsInfo.setText(selectedKeystoreBaseInfo + " • ✓ Alias: " + fastAlias);
                            Toast.makeText(this, "✓ Auto-fetched alias: " + fastAlias, Toast.LENGTH_SHORT).show();
                        } else {
                            autoFetchAliasFromKeystore(false, false);
                        }
                    } else {
                        launchSystemKeystorePicker();
                    }
                })
                .show();
    }

    private void launchSystemKeystorePicker() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        try {
            keystorePickerLauncher.launch(Intent.createChooser(intent, "Select Keystore File"));
        } catch (Exception e) {
            Toast.makeText(this, "No file manager found: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void handlePickedKeystoreUri(Uri uri) {
        executor.execute(() -> {
            File tempKs = null;
            try {
                File tempDir = FileManager.getTempDir(this);
                String pickedName = FileManager.getFileName(this, uri).replaceAll("[^a-zA-Z0-9._-]", "_");
                if (pickedName.isEmpty()) pickedName = "selected_keystore.jks";
                tempKs = new File(tempDir, "ks_" + System.currentTimeMillis() + "_" + pickedName);
                FileManager.copyUriToFile(this, uri, tempKs);
                if (tempKs.length() > 20L * 1024L * 1024L) {
                    tempKs.delete();
                    throw new IllegalArgumentException("Keystore file exceeds 20 MB limit.");
                }

                deleteStaleTempFile(selectedKeystoreFile, tempDir);
                selectedKeystoreFile = tempKs;
                final File acceptedKs = tempKs;
                final String displayName = pickedName;
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    selectedKeystoreBaseInfo = displayName + " (" + AppUtils.formatFileSize(acceptedKs.length()) + ")";
                    tvSelectedKsInfo.setText(selectedKeystoreBaseInfo);
                    etSignKsPass.setText("");
                    aliasManuallyEdited = false;
                    setAliasTextProgrammatically("");
                    autoFetchAliasFromKeystore(false, false);
                });
            } catch (Exception e) {
                if (tempKs != null && tempKs.exists()) tempKs.delete();
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    Toast.makeText(this, "Failed to load Keystore: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void setAliasTextProgrammatically(String alias) {
        settingAliasProgrammatically = true;
        etSignKeyAlias.setText(alias);
        settingAliasProgrammatically = false;
    }

    private void autoFetchAliasFromKeystore(boolean showToastIfFailed, boolean fromPasswordTyping) {
        if (selectedKeystoreFile == null || !selectedKeystoreFile.exists()) {
            if (showToastIfFailed) {
                Toast.makeText(this, "Please select a keystore file first.", Toast.LENGTH_SHORT).show();
            }
            return;
        }

        final File ksFile = selectedKeystoreFile;
        final String password = etSignKsPass.getText().toString();
        final int requestSeq = ++aliasFetchSeq;

        aliasLookupExecutor.execute(() -> {
            List<String> aliases = KeystoreManager.extractAliases(ksFile, password);

            // History lookup only when not validating a newly typed password
            if (aliases.isEmpty() && !fromPasswordTyping) {
                List<HistoryManager.KeystoreRecord> records = HistoryManager.getKeystoreRecords(MainActivity.this);
                for (HistoryManager.KeystoreRecord r : records) {
                    if (r.fileName != null && r.fileName.equalsIgnoreCase(ksFile.getName())) {
                        if (r.alias != null && !r.alias.isEmpty()) {
                            aliases.add(r.alias);
                            break;
                        }
                    }
                }
            }

            final List<String> finalAliases = aliases;
            runOnUiThread(() -> {
                if (!isUiAlive()) return;
                // Ignore stale results if user already switched keystore or kept typing
                if (requestSeq != aliasFetchSeq || selectedKeystoreFile == null || !selectedKeystoreFile.equals(ksFile)) {
                    return;
                }

                if (!finalAliases.isEmpty()) {
                    if (finalAliases.size() == 1) {
                        String foundAlias = finalAliases.get(0);
                        setAliasTextProgrammatically(foundAlias);
                        tvSelectedKsInfo.setText(selectedKeystoreBaseInfo + " • ✓ Alias: " + foundAlias);
                        Toast.makeText(MainActivity.this, "✓ Auto-fetched alias: " + foundAlias, Toast.LENGTH_SHORT).show();
                    } else {
                        String[] items = finalAliases.toArray(new String[0]);
                        new AlertDialog.Builder(MainActivity.this)
                                .setTitle("Select Alias from Keystore")
                                .setItems(items, (dialog, which) -> {
                                    setAliasTextProgrammatically(items[which]);
                                    tvSelectedKsInfo.setText(selectedKeystoreBaseInfo + " • ✓ Alias: " + items[which]);
                                    Toast.makeText(MainActivity.this, "✓ Selected alias: " + items[which], Toast.LENGTH_SHORT).show();
                                })
                                .show();
                    }
                } else {
                    if (!fromPasswordTyping && password.isEmpty()) {
                        tvSelectedKsInfo.setText(selectedKeystoreBaseInfo + " • Enter Keystore Password to auto-fetch alias");
                    }
                    if (showToastIfFailed) {
                        if (password.isEmpty()) {
                            Toast.makeText(MainActivity.this, "Encrypted keystore: enter Keystore Password below to auto-fetch alias.", Toast.LENGTH_LONG).show();
                        } else {
                            Toast.makeText(MainActivity.this, "Incorrect password or unsupported keystore.", Toast.LENGTH_SHORT).show();
                        }
                    }
                }
            });
        });
    }

    private void addConsoleStep(String icon, String timeText, String desc) {
        runOnUiThread(() -> {
            if (!isUiAlive()) return;
            View stepView = LayoutInflater.from(this).inflate(R.layout.item_build_step, layoutConsoleSteps, false);
            TextView tvIcon = stepView.findViewById(R.id.tv_step_icon);
            TextView tvTime = stepView.findViewById(R.id.tv_step_time);
            TextView tvDesc = stepView.findViewById(R.id.tv_step_desc);

            tvIcon.setText(icon);
            tvIcon.setTextColor(ContextCompat.getColor(
                    this,
                    "✗".equals(icon) ? R.color.console_error : R.color.console_success
            ));
            tvTime.setText(timeText);
            tvDesc.setText(desc);

            stepView.setAlpha(0f);
            stepView.setTranslationY(8f);
            layoutConsoleSteps.addView(stepView);
            stepView.animate().alpha(1f).translationY(0f).setDuration(160).start();
        });
    }

    private void runApkToAabProcess() {
        if (selectedApkFile == null || !selectedApkFile.exists()) {
            Toast.makeText(this, "Please select an APK file first.", Toast.LENGTH_SHORT).show();
            return;
        }

        if (selectedKeystoreFile == null || !selectedKeystoreFile.exists()) {
            Toast.makeText(this, "Please select a Keystore file.", Toast.LENGTH_SHORT).show();
            return;
        }

        String ksPassword = etSignKsPass.getText().toString();
        String keyAlias = etSignKeyAlias.getText().toString();
        String keyPassword = etSignKeyPass.getText().toString();
        String outName = etOutputBundleName.getText().toString().trim();

        if (ksPassword.isEmpty() || keyAlias.isEmpty() || keyPassword.isEmpty()) {
            Toast.makeText(this, "Please enter Keystore Password, Key Alias and Key Password.", Toast.LENGTH_SHORT).show();
            return;
        }

        if (outName.isEmpty()) {
            outName = "app-bundle.aab";
        }

        // HIDE ALL INPUTS & DISPLAY PROGRESS CONSOLE
        layoutConversionInputs.setVisibility(View.GONE);
        layoutConversionResult.setVisibility(View.GONE);
        btnRetryConversion.setVisibility(View.GONE);

        cardBuildConsole.setVisibility(View.VISIBLE);
        animateReveal(cardBuildConsole);
        pbConsoleSpinner.setVisibility(View.VISIBLE);
        tvConsoleStatus.setText("Building & Signing Package...");
        tvConsoleStatus.setTextColor(ContextCompat.getColor(this, R.color.console_accent));
        layoutConsoleSteps.removeAllViews();

        final String finalOutName = outName;
        final long startTime = System.currentTimeMillis();

        executor.execute(() -> {
            File tempBundleFile = null;
            try {
                File exportsDir = FileManager.getExportsDir(this);
                File tempDir = FileManager.getTempDir(this);
                long estRequired = Math.max(selectedApkFile.length() * 2L, 10L * 1024L * 1024L);
                if (!StorageHelper.hasEnoughStorage(tempDir, estRequired)
                        || !StorageHelper.hasEnoughStorage(exportsDir, estRequired)) {
                    throw new IllegalStateException("Insufficient free storage space to build & sign AAB.");
                }

                // Step 1: Validate APK
                ApkFileManager.ApkAnalysis apkCheck = ApkFileManager.analyzeApk(selectedApkFile);
                if (!apkCheck.isValidApk) {
                    throw new IllegalStateException("Invalid source APK: " + apkCheck.errorMessage);
                }
                addConsoleStep("✓", String.format(Locale.US, "+%.2fs", (System.currentTimeMillis() - startTime) / 1000.0), "Validated source APK package integrity");

                // Step 2: Bundle Reconstruction
                BundleConverter.ConversionReport report = BundleConverter.evaluateAndReconstruct(
                        selectedApkFile,
                        tempDir,
                        "temp_bundle.aab"
                );
                tempBundleFile = report.reconstructedArchive;

                if (report.reconstructedArchive == null) {
                    throw new IllegalStateException("Reconstruction failed: " + report.errorMessage);
                }

                addConsoleStep("✓", String.format(Locale.US, "+%.2fs", (System.currentTimeMillis() - startTime) / 1000.0),
                        "Compiled resources.pb, BundleConfig.pb & " + report.protoXmlCount + " proto XMLs");

                // Step 3: Keystore Auth (supports PKCS12, BKS, and Pure Java JKS)
                KeyStore ks = KeystoreManager.loadKeystoreForSigning(selectedKeystoreFile, ksPassword, keyAlias, keyPassword);
                if (!ks.containsAlias(keyAlias)) {
                    throw new IllegalArgumentException("Alias '" + keyAlias + "' was not found in keystore.");
                }

                addConsoleStep("✓", String.format(Locale.US, "+%.2fs", (System.currentTimeMillis() - startTime) / 1000.0), "Keystore unlocked & alias '" + keyAlias + "' authenticated");

                // Step 4: Sign bundle & generate digests
                AabSigner.SigningResult signResult = AabSigner.signArchive(
                        report.reconstructedArchive,
                        exportsDir,
                        finalOutName,
                        ks,
                        keyAlias,
                        keyPassword
                );

                if (!signResult.isSuccess) {
                    throw new IllegalStateException("Signing failed: " + signResult.errorMessage);
                }

                finalSignedBundleFile = signResult.signedFile;
                addConsoleStep("✓", String.format(Locale.US, "+%.2fs", (System.currentTimeMillis() - startTime) / 1000.0),
                        "Signed archive using " + signResult.signatureAlgorithm);

                // Step 5: Verify cryptographic signature & entry digests
                X509Certificate cert = (X509Certificate) ks.getCertificate(keyAlias);
                AabValidator.ValidationResult valResult = AabValidator.verifySignedArchive(finalSignedBundleFile, cert);
                if (!valResult.isValid) {
                    throw new IllegalStateException("Post-signing validation failed: " + valResult.errorMessage);
                }

                addConsoleStep("✓", String.format(Locale.US, "+%.2fs", (System.currentTimeMillis() - startTime) / 1000.0),
                        "Signature & digest integrity verified (" + valResult.verifiedEntriesCount + " entries)");

                // Store Technical Report for dialog
                StringBuilder fullReport = new StringBuilder();
                fullReport.append(report.technicalAnalysis).append("\n\n");
                fullReport.append("SIGNING & VERIFICATION STATUS:\n");
                fullReport.append("• Signer Alias: ").append(signResult.alias).append("\n");
                fullReport.append("• Certificate SHA-256: ").append(signResult.certificateSha256).append("\n");
                fullReport.append("• Algorithm: ").append(signResult.signatureAlgorithm).append("\n");
                fullReport.append("• Entries Signed & Verified: ").append(valResult.verifiedEntriesCount).append(" entries\n");
                fullReport.append("• Output Location: ").append(finalSignedBundleFile.getAbsolutePath()).append("\n");
                lastTechnicalReport = fullReport.toString();

                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    pbConsoleSpinner.setVisibility(View.GONE);
                    tvConsoleStatus.setText("Build & Signing Completed Successfully!");
                    tvConsoleStatus.setTextColor(ContextCompat.getColor(MainActivity.this, R.color.console_success));

                    // Clear password fields from UI
                    etSignKsPass.setText("");
                    etSignKeyPass.setText("");

                    // Show concise clean summary card
                    layoutConversionResult.setVisibility(View.VISIBLE);
                    animateReveal(layoutConversionResult);
                    performConfirmHaptic(layoutConversionResult);
                    tvConvOutputName.setText(finalSignedBundleFile.getName());
                    tvConvSize.setText(AppUtils.formatFileSize(finalSignedBundleFile.length()));
                    tvConvSigningStatus.setText(signResult.signatureAlgorithm);
                    tvConvKeyInfo.setText(selectedKeystoreFile.getName() + " (" + keyAlias + ")");
                    tvConvSha256.setText(signResult.certificateSha256);
                    tvConvPath.setText(finalSignedBundleFile.getAbsolutePath());

                    // Save record to persistent history
                    HistoryManager.saveAabRecord(MainActivity.this, new HistoryManager.AabRecord(
                            selectedApkFile.getName(),
                            finalSignedBundleFile.getName(),
                            AppUtils.formatFileSize(finalSignedBundleFile.length()),
                            selectedKeystoreFile.getName() + " (" + keyAlias + ")",
                            signResult.certificateSha256,
                            finalSignedBundleFile.getAbsolutePath(),
                            "Signed (" + signResult.signatureAlgorithm + ")",
                            System.currentTimeMillis()
                    ));

                    Toast.makeText(MainActivity.this, "Bundle created, signed and verified!", Toast.LENGTH_SHORT).show();
                });

            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (!isUiAlive()) return;
                    pbConsoleSpinner.setVisibility(View.GONE);
                    tvConsoleStatus.setText("Build Failed: " + e.getMessage());
                    tvConsoleStatus.setTextColor(ContextCompat.getColor(MainActivity.this, R.color.console_error));
                    btnRetryConversion.setVisibility(View.VISIBLE);
                    addConsoleStep("✗", String.format(Locale.US, "+%.2fs", (System.currentTimeMillis() - startTime) / 1000.0), "Error: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "Process failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            } finally {
                if (tempBundleFile != null && tempBundleFile.exists()) {
                    tempBundleFile.delete();
                }
            }
        });
    }

    // ==========================================
    // DRAWER GUIDES & DIALOGS
    // ==========================================
    private void showHowToUseDialog() {
        new AlertDialog.Builder(this)
                .setTitle("DevLoveTool Guide")
                .setMessage("1. Installed Apps Explorer:\n" +
                        "• Tap any app to inspect complete specifications in a unified scroll view.\n" +
                        "• Long press any value to select and copy text.\n" +
                        "• Save APK to any folder or share directly.\n\n" +
                        "2. Keystore Generator:\n" +
                        "• Generates standard 2048-bit RSA keys with X.509 self-signed certificates (default 100 years validity).\n" +
                        "• Supported formats: .jks (default) and .p12 (PKCS12).\n" +
                        "• Toggle password eye icon to verify passwords before generating.\n\n" +
                        "3. APK to AAB + Signer:\n" +
                        "• Selecting a keystore automatically detects its Key Alias.\n" +
                        "• Reconstructs base bundle hierarchy and signs archive with SHA256withRSA.\n" +
                        "• Save outputs to any folder of your choice or open full History view.")
                .setPositiveButton("Got It", null)
                .show();
    }

    private void showPrivacyPolicyDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Privacy Policy & Terms")
                .setMessage("DevLoveTool is a 100% offline developer toolkit.\n\n" +
                        "• Zero Internet Permissions: This app does not declare or request INTERNET permission. No data ever leaves your device.\n" +
                        "• Local Data Security: Private keys, certificates, and passwords are processed in-memory and cleared immediately after cryptographic use.\n" +
                        "• Folder Export Control: Files are saved to any folder only when you explicitly choose a destination via Android Storage Access.\n" +
                        "• Open Tool Terms: Provided as a native developer tool under standard MIT/Apache developer terms.")
                .setPositiveButton("Agree & Close", null)
                .show();
    }

    private void showRatingDialog() {
        String[] stars = {"⭐⭐⭐⭐⭐ (5/5 Excellent)", "⭐⭐⭐⭐ (4/5 Great)", "⭐⭐⭐ (3/5 Good)", "⭐⭐ (2/5 Fair)", "⭐ (1/5 Needs Work)"};
        final int[] chosenIndex = {0};
        new AlertDialog.Builder(this)
                .setTitle("Rate DevLoveTool")
                .setSingleChoiceItems(stars, 0, (d, idx) -> chosenIndex[0] = idx)
                .setPositiveButton("Submit", (dialog, which) -> {
                    int starCount = 5 - chosenIndex[0];
                    String unit = starCount == 1 ? " star!" : " stars!";
                    Toast.makeText(this, "Thank you for rating DevLoveTool " + starCount + unit, Toast.LENGTH_LONG).show();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showReportDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Report an Issue")
                .setMessage("Encountered a bug, crash, or unexpected behavior?\n\nContact developer directly with logs or feedback.")
                .setPositiveButton("Send Email", (dialog, which) -> {
                    Intent intent = new Intent(Intent.ACTION_SENDTO);
                    intent.setData(Uri.parse("mailto:uditkm143@gmail.com"));
                    intent.putExtra(Intent.EXTRA_SUBJECT, "[DevLoveTool Bug Report]");
                    intent.putExtra(Intent.EXTRA_TEXT, "Device: " + android.os.Build.MODEL + " (Android " + android.os.Build.VERSION.RELEASE + ")\n\nIssue Details:\n");
                    try {
                        startActivity(Intent.createChooser(intent, "Send Bug Report"));
                    } catch (Exception e) {
                        Toast.makeText(this, "Email client not found. Contact: uditkm143@gmail.com", Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showJoinCommunityDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Join Developer Community")
                .setMessage("Connect with other Android & Sketchware Pro developers, share tips, keystore workflows, and APK/AAB tools.\n\nChannel: @DevLoveTool")
                .setPositiveButton("Open Channel", (dialog, which) -> {
                    Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/DevLoveTool"));
                    try {
                        startActivity(intent);
                    } catch (Exception e) {
                        Toast.makeText(this, "Telegram/Browser not available: https://t.me/DevLoveTool", Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton("Close", null)
                .show();
    }

    private void showDeveloperContactDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Developer Contact")
                .setMessage("Lead Developer: Udit Kumar\nEmail: uditkm143@gmail.com\nSpecialty: Pure Java Android Architecture, Sketchware Pro Tooling & Native Security.")
                .setPositiveButton("Send Email", (dialog, which) -> {
                    Intent intent = new Intent(Intent.ACTION_SENDTO);
                    intent.setData(Uri.parse("mailto:uditkm143@gmail.com"));
                    intent.putExtra(Intent.EXTRA_SUBJECT, "[DevLoveTool Inquiry]");
                    try {
                        startActivity(Intent.createChooser(intent, "Contact Developer"));
                    } catch (Exception e) {
                        Toast.makeText(this, "Contact email: uditkm143@gmail.com", Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton("Close", null)
                .show();
    }
}
