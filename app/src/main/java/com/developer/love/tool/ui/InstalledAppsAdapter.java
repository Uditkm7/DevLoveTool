package com.developer.love.tool.ui;

import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.developer.love.tool.R;
import com.developer.love.tool.core.AppUtils;
import com.developer.love.tool.installedapps.AppInfoModel;
import com.developer.love.tool.installedapps.InstalledAppsManager;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class InstalledAppsAdapter extends RecyclerView.Adapter<InstalledAppsAdapter.AppViewHolder> {

    public interface OnAppClickListener {
        void onAppClick(AppInfoModel app);
    }

    private static final ExecutorService iconExecutor = Executors.newFixedThreadPool(2);
    private static final Handler mainHandler = new Handler(Looper.getMainLooper());

    private final Context context;
    private final boolean compactPickerMode;
    private final List<AppInfoModel> appList = new ArrayList<>();
    private final OnAppClickListener listener;

    public InstalledAppsAdapter(Context context, OnAppClickListener listener) {
        this(context, false, listener);
    }

    public InstalledAppsAdapter(Context context, boolean compactPickerMode, OnAppClickListener listener) {
        this.context = context;
        this.compactPickerMode = compactPickerMode;
        this.listener = listener;
    }

    public void updateList(List<AppInfoModel> newItems) {
        appList.clear();
        if (newItems != null) {
            appList.addAll(newItems);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public AppViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        int layoutRes = compactPickerMode ? R.layout.item_picker_app_row : R.layout.item_app_row;
        View v = LayoutInflater.from(context).inflate(layoutRes, parent, false);
        return new AppViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull AppViewHolder holder, int position) {
        AppInfoModel item = appList.get(position);
        String pkg = item.getPackageName();

        holder.tvAppName.setText(item.getAppName());
        holder.tvPackageName.setText(pkg);
        String vName = item.getVersionName() != null ? item.getVersionName() : "N/A";
        holder.tvVersion.setText("v" + vName + " (" + item.getVersionCode() + ")");

        if (item.getAppSize() > 0) {
            holder.tvAppSize.setText(AppUtils.formatFileSize(item.getAppSize()));
            holder.tvAppSize.setVisibility(View.VISIBLE);
        } else {
            holder.tvAppSize.setVisibility(View.GONE);
        }

        // Fast cached icon or lazy background icon loading
        holder.ivAppIcon.setTag(pkg);
        Drawable icon = item.getIcon();
        if (icon == null) {
            icon = InstalledAppsManager.getCachedIcon(pkg);
            if (icon != null) {
                item.setIcon(icon);
            }
        }

        holder.ivAppIcon.animate().cancel();
        holder.ivAppIcon.setAlpha(1f);

        if (icon != null) {
            holder.ivAppIcon.setImageDrawable(icon);
        } else {
            holder.ivAppIcon.setImageResource(R.drawable.ic_apps);
            final PackageManager pm = context.getApplicationContext().getPackageManager();
            iconExecutor.execute(() -> {
                try {
                    Drawable loaded = pm.getApplicationIcon(pkg);
                    if (loaded != null) {
                        InstalledAppsManager.putCachedIcon(pkg, loaded);
                        item.setIcon(loaded);
                        mainHandler.post(() -> {
                            Object tag = holder.ivAppIcon.getTag();
                            if (pkg.equals(tag)) {
                                holder.ivAppIcon.setAlpha(0f);
                                holder.ivAppIcon.setImageDrawable(loaded);
                                holder.ivAppIcon.animate().alpha(1f).setDuration(140).start();
                            }
                        });
                    }
                } catch (Exception ignored) {}
            });
        }

        holder.itemView.setOnClickListener(v -> {
            if (listener != null) {
                listener.onAppClick(item);
            }
        });
    }

    @Override
    public int getItemCount() {
        return appList.size();
    }

    static class AppViewHolder extends RecyclerView.ViewHolder {
        ImageView ivAppIcon;
        TextView tvAppName;
        TextView tvPackageName;
        TextView tvVersion;
        TextView tvAppSize;

        public AppViewHolder(@NonNull View itemView) {
            super(itemView);
            ivAppIcon = itemView.findViewById(R.id.iv_app_icon);
            tvAppName = itemView.findViewById(R.id.tv_app_name);
            tvPackageName = itemView.findViewById(R.id.tv_package_name);
            tvVersion = itemView.findViewById(R.id.tv_version);
            tvAppSize = itemView.findViewById(R.id.tv_app_size);
        }
    }
}
