package com.developer.love.tool.history;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.developer.love.tool.R;
import com.developer.love.tool.core.AppUtils;
import com.developer.love.tool.storage.FileManager;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class HistoryAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    public static final int TYPE_KEYSTORE = 1;
    public static final int TYPE_AAB = 2;

    public interface OnHistoryFileActionListener {
        void onSaveToFolder(File file);
        void onShareFile(File file);
    }

    public static class HistoryItem {
        public final int type;
        public final long timestamp;
        public final HistoryManager.KeystoreRecord keystoreRecord;
        public final HistoryManager.AabRecord aabRecord;

        public HistoryItem(HistoryManager.KeystoreRecord record) {
            this.type = TYPE_KEYSTORE;
            this.timestamp = record.timestamp;
            this.keystoreRecord = record;
            this.aabRecord = null;
        }

        public HistoryItem(HistoryManager.AabRecord record) {
            this.type = TYPE_AAB;
            this.timestamp = record.timestamp;
            this.keystoreRecord = null;
            this.aabRecord = record;
        }
    }

    private final Context context;
    private final OnHistoryFileActionListener actionListener;
    private final List<HistoryItem> items = new ArrayList<>();

    public HistoryAdapter(Context context, OnHistoryFileActionListener actionListener) {
        this.context = context;
        this.actionListener = actionListener;
    }

    public void setItems(List<HistoryItem> newItems) {
        this.items.clear();
        if (newItems != null) {
            this.items.addAll(newItems);
        }
        Collections.sort(this.items, (a, b) -> Long.compare(b.timestamp, a.timestamp));
        notifyDataSetChanged();
    }

    @Override
    public int getItemViewType(int position) {
        return items.get(position).type;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
        if (viewType == TYPE_KEYSTORE) {
            View view = inflater.inflate(R.layout.item_history_keystore, parent, false);
            return new KeystoreViewHolder(view);
        } else {
            View view = inflater.inflate(R.layout.item_history_aab, parent, false);
            return new AabViewHolder(view);
        }
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        HistoryItem wrapper = items.get(position);
        if (holder instanceof KeystoreViewHolder && wrapper.keystoreRecord != null) {
            HistoryManager.KeystoreRecord item = wrapper.keystoreRecord;
            KeystoreViewHolder vh = (KeystoreViewHolder) holder;
            vh.tvName.setText(item.fileName);
            vh.tvTime.setText(item.timestamp > 0 ? "Created: " + AppUtils.formatDate(item.timestamp) : "Created: N/A");
            vh.tvFormat.setText(item.format);
            vh.tvAlias.setText(item.alias);
            vh.tvValidity.setText(item.validityYears + (item.validityYears == 1 ? " Year" : " Years"));
            vh.tvSha256.setText(item.sha256 != null && !item.sha256.isEmpty() ? item.sha256 : "N/A");
            vh.tvPath.setText(item.filePath != null && !item.filePath.isEmpty() ? item.filePath : "N/A");

            vh.btnSave.setOnClickListener(v -> handleFileAction(item.filePath, true));
            vh.btnShare.setOnClickListener(v -> handleFileAction(item.filePath, false));

        } else if (holder instanceof AabViewHolder && wrapper.aabRecord != null) {
            HistoryManager.AabRecord item = wrapper.aabRecord;
            AabViewHolder vh = (AabViewHolder) holder;
            vh.tvName.setText(item.aabName);
            vh.tvTime.setText(item.timestamp > 0 ? "Built: " + AppUtils.formatDate(item.timestamp) : "Built: N/A");
            vh.tvSize.setText(item.fileSize != null && !item.fileSize.isEmpty() ? item.fileSize : "N/A");
            vh.tvSource.setText(item.apkName != null && !item.apkName.isEmpty() ? item.apkName : "N/A");
            vh.tvStatus.setText(item.status != null && !item.status.isEmpty() ? item.status : "Signed");
            vh.tvKey.setText(item.signedKeyAlias != null && !item.signedKeyAlias.isEmpty() ? item.signedKeyAlias : "N/A");
            vh.tvSha256.setText(item.sha256 != null && !item.sha256.isEmpty() ? item.sha256 : "N/A");
            vh.tvPath.setText(item.filePath != null && !item.filePath.isEmpty() ? item.filePath : "N/A");

            vh.btnSave.setOnClickListener(v -> handleFileAction(item.filePath, true));
            vh.btnShare.setOnClickListener(v -> handleFileAction(item.filePath, false));
        }
    }

    private void handleFileAction(String filePath, boolean isSaveToFolder) {
        if (filePath == null || filePath.isEmpty()) {
            Toast.makeText(context, "File path unavailable.", Toast.LENGTH_SHORT).show();
            return;
        }
        File file = new File(filePath);
        if (!file.exists()) {
            Toast.makeText(context, "File no longer exists on disk.", Toast.LENGTH_SHORT).show();
            return;
        }
        if (actionListener != null) {
            if (isSaveToFolder) {
                actionListener.onSaveToFolder(file);
            } else {
                actionListener.onShareFile(file);
            }
        } else if (!isSaveToFolder) {
            FileManager.shareFile(context, file, "application/octet-stream");
        }
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class KeystoreViewHolder extends RecyclerView.ViewHolder {
        TextView tvName, tvTime, tvFormat, tvAlias, tvValidity, tvSha256, tvPath;
        MaterialButton btnSave, btnShare;

        KeystoreViewHolder(@NonNull View itemView) {
            super(itemView);
            tvName = itemView.findViewById(R.id.tv_hist_ks_name);
            tvTime = itemView.findViewById(R.id.tv_hist_ks_time);
            tvFormat = itemView.findViewById(R.id.tv_hist_ks_format);
            tvAlias = itemView.findViewById(R.id.tv_hist_ks_alias);
            tvValidity = itemView.findViewById(R.id.tv_hist_ks_validity);
            tvSha256 = itemView.findViewById(R.id.tv_hist_ks_sha256);
            tvPath = itemView.findViewById(R.id.tv_hist_ks_path);
            btnSave = itemView.findViewById(R.id.btn_hist_ks_save);
            btnShare = itemView.findViewById(R.id.btn_hist_ks_share);
        }
    }

    static class AabViewHolder extends RecyclerView.ViewHolder {
        TextView tvName, tvTime, tvSize, tvSource, tvStatus, tvKey, tvSha256, tvPath;
        MaterialButton btnSave, btnShare;

        AabViewHolder(@NonNull View itemView) {
            super(itemView);
            tvName = itemView.findViewById(R.id.tv_hist_aab_name);
            tvTime = itemView.findViewById(R.id.tv_hist_aab_time);
            tvSize = itemView.findViewById(R.id.tv_hist_aab_size);
            tvSource = itemView.findViewById(R.id.tv_hist_aab_source);
            tvStatus = itemView.findViewById(R.id.tv_hist_aab_status);
            tvKey = itemView.findViewById(R.id.tv_hist_aab_key);
            tvSha256 = itemView.findViewById(R.id.tv_hist_aab_sha256);
            tvPath = itemView.findViewById(R.id.tv_hist_aab_path);
            btnSave = itemView.findViewById(R.id.btn_hist_aab_save);
            btnShare = itemView.findViewById(R.id.btn_hist_aab_share);
        }
    }
}
