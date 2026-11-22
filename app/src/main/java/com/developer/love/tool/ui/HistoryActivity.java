package com.developer.love.tool.ui;

import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.transition.TransitionManager;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
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
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.developer.love.tool.R;
import com.developer.love.tool.history.HistoryAdapter;
import com.developer.love.tool.history.HistoryManager;
import com.developer.love.tool.storage.FileManager;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HistoryActivity extends AppCompatActivity {

    private static final int FILTER_ALL = 0;
    private static final int FILTER_KEYSTORES = 1;
    private static final int FILTER_AABS = 2;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private TextView tvSummaryCount;
    private EditText etSearch;
    private RadioGroup rgFilter;
    private RadioButton rbAll;
    private RadioButton rbKeystores;
    private RadioButton rbAabs;
    private RecyclerView rvHistory;
    private LinearLayout layoutEmpty;
    private TextView tvEmptyTitle;
    private TextView tvEmptyDesc;

    private HistoryAdapter adapter;
    private int currentFilter = FILTER_ALL;
    private File pendingSaveFile = null;

    private final ActivityResultLauncher<String> saveToFolderLauncher = registerForActivityResult(
            new ActivityResultContracts.CreateDocument("*/*"),
            uri -> {
                if (uri != null && pendingSaveFile != null) {
                    copyPendingFileToUri(uri);
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
        setContentView(R.layout.activity_history);

        initViews();
        setupEdgeToEdgeInsets();
        loadAndFilterHistory();
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
        View topBar = findViewById(R.id.top_bar_history);
        final int topPadLeft = topBar.getPaddingLeft();
        final int topPadTop = topBar.getPaddingTop();
        final int topPadRight = topBar.getPaddingRight();
        final int topPadBottom = topBar.getPaddingBottom();

        ViewCompat.setOnApplyWindowInsetsListener(topBar, (v, insets) -> {
            Insets sysBars = insets.getInsets(WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            v.setPadding(topPadLeft + sysBars.left, topPadTop + sysBars.top, topPadRight + sysBars.right, topPadBottom);
            return insets;
        });

        final int rvPadLeft = rvHistory.getPaddingLeft();
        final int rvPadTop = rvHistory.getPaddingTop();
        final int rvPadRight = rvHistory.getPaddingRight();
        final int rvPadBottom = rvHistory.getPaddingBottom();

        final Insets[] lastSysBars = {Insets.NONE};
        final Insets[] lastIme = {Insets.NONE};
        final boolean[] lastImeVisible = {false};

        final Runnable reconcileRvPadding = () -> {
            if (isFinishing() || isDestroyed()) return;
            Insets sysBars = lastSysBars[0];
            Insets ime = lastIme[0];
            int targetCover = lastImeVisible[0] ? Math.max(ime.bottom, sysBars.bottom) : sysBars.bottom;

            View decorView = getWindow().getDecorView();
            int decorHeight = decorView != null ? decorView.getHeight() : 0;
            int overlapBottom = targetCover;
            if (decorHeight > 0 && rvHistory.getHeight() > 0) {
                int[] rvLoc = new int[2];
                rvHistory.getLocationInWindow(rvLoc);
                int rvBottom = rvLoc[1] + rvHistory.getHeight();
                overlapBottom = Math.max(0, rvBottom - (decorHeight - targetCover));
            }

            int pLeft = rvPadLeft + sysBars.left;
            int pRight = rvPadRight + sysBars.right;
            int pBottom = rvPadBottom + overlapBottom;
            if (rvHistory.getPaddingLeft() != pLeft
                    || rvHistory.getPaddingTop() != rvPadTop
                    || rvHistory.getPaddingRight() != pRight
                    || rvHistory.getPaddingBottom() != pBottom) {
                rvHistory.setPadding(pLeft, rvPadTop, pRight, pBottom);
            }
        };

        ViewCompat.setOnApplyWindowInsetsListener(rvHistory, (v, insets) -> {
            Insets sysBars = insets.getInsets(WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            Insets ime = insets.getInsets(WindowInsetsCompat.Type.ime());
            lastSysBars[0] = sysBars;
            lastIme[0] = ime;
            lastImeVisible[0] = insets.isVisible(WindowInsetsCompat.Type.ime()) || ime.bottom > sysBars.bottom;
            reconcileRvPadding.run();
            return insets;
        });

        rvHistory.addOnLayoutChangeListener((v, left, top, right, bottom, oldLeft, oldTop, oldRight, oldBottom) -> {
            if ((bottom - top) != (oldBottom - oldTop) || lastImeVisible[0]) {
                rvHistory.post(reconcileRvPadding);
            }
        });
    }

    private void initViews() {
        ImageButton btnBack = findViewById(R.id.btn_back_history);
        btnBack.setOnClickListener(v -> finish());

        tvSummaryCount = findViewById(R.id.tv_history_summary_count);
        etSearch = findViewById(R.id.et_history_search);
        rgFilter = findViewById(R.id.rg_history_filter);
        rbAll = findViewById(R.id.rb_hist_all);
        rbKeystores = findViewById(R.id.rb_hist_keystores);
        rbAabs = findViewById(R.id.rb_hist_aabs);
        rvHistory = findViewById(R.id.rv_history_full);
        layoutEmpty = findViewById(R.id.layout_history_empty);
        tvEmptyTitle = findViewById(R.id.tv_history_empty_title);
        tvEmptyDesc = findViewById(R.id.tv_history_empty_desc);

        MaterialButton btnClearAll = findViewById(R.id.btn_clear_all_history);
        btnClearAll.setOnClickListener(v -> confirmClearAll());

        rvHistory.setLayoutManager(new LinearLayoutManager(this));
        adapter = new HistoryAdapter(this, new HistoryAdapter.OnHistoryFileActionListener() {
            @Override
            public void onSaveToFolder(File file) {
                pendingSaveFile = file;
                saveToFolderLauncher.launch(file.getName());
            }

            @Override
            public void onShareFile(File file) {
                FileManager.shareFile(HistoryActivity.this, file, "application/octet-stream");
            }
        });
        rvHistory.setAdapter(adapter);

        rgFilter.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.rb_hist_all) {
                currentFilter = FILTER_ALL;
            } else if (checkedId == R.id.rb_hist_keystores) {
                currentFilter = FILTER_KEYSTORES;
            } else {
                currentFilter = FILTER_AABS;
            }
            group.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
            TransitionManager.beginDelayedTransition(rgFilter);
            updateTabStyles();
            loadAndFilterHistory();
        });

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                loadAndFilterHistory();
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });
    }

    private void updateTabStyles() {
        styleTab(rbAll, currentFilter == FILTER_ALL);
        styleTab(rbKeystores, currentFilter == FILTER_KEYSTORES);
        styleTab(rbAabs, currentFilter == FILTER_AABS);
    }

    private void styleTab(RadioButton rb, boolean active) {
        if (active) {
            rb.setBackgroundResource(R.drawable.bg_segment_active);
            rb.setTextColor(ContextCompat.getColor(this, R.color.text_primary));
        } else {
            rb.setBackgroundColor(Color.TRANSPARENT);
            rb.setTextColor(ContextCompat.getColor(this, R.color.secondary));
        }
    }

    private void loadAndFilterHistory() {
        List<HistoryManager.KeystoreRecord> ksList = HistoryManager.getKeystoreRecords(this);
        List<HistoryManager.AabRecord> aabList = HistoryManager.getAabRecords(this);

        int total = ksList.size() + aabList.size();
        rbAll.setText("All (" + total + ")");
        rbKeystores.setText("Keystores (" + ksList.size() + ")");
        rbAabs.setText("AABs (" + aabList.size() + ")");

        String query = etSearch.getText().toString().toLowerCase(Locale.getDefault()).trim();
        List<HistoryAdapter.HistoryItem> filtered = new ArrayList<>();

        if (currentFilter == FILTER_ALL || currentFilter == FILTER_KEYSTORES) {
            for (HistoryManager.KeystoreRecord r : ksList) {
                if (matchesKeystore(r, query)) {
                    filtered.add(new HistoryAdapter.HistoryItem(r));
                }
            }
        }

        if (currentFilter == FILTER_ALL || currentFilter == FILTER_AABS) {
            for (HistoryManager.AabRecord r : aabList) {
                if (matchesAab(r, query)) {
                    filtered.add(new HistoryAdapter.HistoryItem(r));
                }
            }
        }

        adapter.setItems(filtered);
        tvSummaryCount.setText(filtered.size() + " of " + total + " records shown");

        if (filtered.isEmpty()) {
            layoutEmpty.setVisibility(View.VISIBLE);
            if (!query.isEmpty()) {
                tvEmptyTitle.setText("No Matching Records");
                tvEmptyDesc.setText("Try another search term for filename, alias, SHA-256, or path.");
            } else {
                tvEmptyTitle.setText("No History Records Yet");
                tvEmptyDesc.setText("Generated keystores and signed AAB bundles will appear here with full details.");
            }
        } else {
            layoutEmpty.setVisibility(View.GONE);
        }
    }

    private boolean matchesKeystore(HistoryManager.KeystoreRecord r, String q) {
        if (q.isEmpty()) return true;
        return contains(r.fileName, q)
                || contains(r.alias, q)
                || contains(r.format, q)
                || contains(r.sha256, q)
                || contains(r.filePath, q);
    }

    private boolean matchesAab(HistoryManager.AabRecord r, String q) {
        if (q.isEmpty()) return true;
        return contains(r.aabName, q)
                || contains(r.apkName, q)
                || contains(r.signedKeyAlias, q)
                || contains(r.sha256, q)
                || contains(r.filePath, q)
                || contains(r.status, q);
    }

    private boolean contains(String field, String q) {
        return field != null && field.toLowerCase(Locale.getDefault()).contains(q);
    }

    private void confirmClearAll() {
        new AlertDialog.Builder(this)
                .setTitle("Clear All History")
                .setMessage("Are you sure you want to clear all history logs? Saved keystore and AAB files on your storage will remain untouched.")
                .setPositiveButton("Clear", (d, w) -> {
                    HistoryManager.clearHistory(this);
                    loadAndFilterHistory();
                    Toast.makeText(this, "History cleared.", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void copyPendingFileToUri(Uri destUri) {
        final File source = pendingSaveFile;
        pendingSaveFile = null;
        if (source == null || !source.exists()) return;

        executor.execute(() -> {
            try {
                FileManager.copyFileToUri(this, source, destUri);
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    Toast.makeText(this, "Saved '" + source.getName() + "' to selected folder!", Toast.LENGTH_LONG).show();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    Toast.makeText(this, "Save failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }
}
