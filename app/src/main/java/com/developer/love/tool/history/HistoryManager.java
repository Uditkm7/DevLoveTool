package com.developer.love.tool.history;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages persistent local history of generated keystores and signed AAB conversions.
 * Pure Java using standard Android SharedPreferences and org.json.
 */
public class HistoryManager {

    private static final String PREF_NAME = "devlovetool_history";
    private static final String KEY_KEYSTORES = "hist_keystores";
    private static final String KEY_AAB = "hist_aab_conversions";

    public static class KeystoreRecord implements Serializable {
        public String fileName;
        public String format;
        public String alias;
        public int validityYears;
        public String sha256;
        public String filePath;
        public long timestamp;

        public KeystoreRecord(String fileName, String format, String alias, int validityYears, String sha256, String filePath, long timestamp) {
            this.fileName = fileName;
            this.format = format;
            this.alias = alias;
            this.validityYears = validityYears;
            this.sha256 = sha256;
            this.filePath = filePath;
            this.timestamp = timestamp;
        }
    }

    public static class AabRecord implements Serializable {
        public String apkName;
        public String aabName;
        public String fileSize;
        public String signedKeyAlias;
        public String sha256;
        public String filePath;
        public String status;
        public long timestamp;

        public AabRecord(String apkName, String aabName, String fileSize, String signedKeyAlias, String sha256, String filePath, String status, long timestamp) {
            this.apkName = apkName;
            this.aabName = aabName;
            this.fileSize = fileSize;
            this.signedKeyAlias = signedKeyAlias;
            this.sha256 = sha256;
            this.filePath = filePath;
            this.status = status;
            this.timestamp = timestamp;
        }
    }

    public static void saveKeystoreRecord(Context context, KeystoreRecord record) {
        try {
            SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            String jsonStr = sp.getString(KEY_KEYSTORES, "[]");
            JSONArray array = new JSONArray(jsonStr);

            JSONObject obj = new JSONObject();
            obj.put("fileName", record.fileName);
            obj.put("format", record.format);
            obj.put("alias", record.alias);
            obj.put("validityYears", record.validityYears);
            obj.put("sha256", record.sha256);
            obj.put("filePath", record.filePath);
            obj.put("timestamp", record.timestamp);

            // Put latest on top
            JSONArray newArray = new JSONArray();
            newArray.put(obj);
            for (int i = 0; i < array.length() && i < 99; i++) {
                newArray.put(array.get(i));
            }
            sp.edit().putString(KEY_KEYSTORES, newArray.toString()).apply();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static List<KeystoreRecord> getKeystoreRecords(Context context) {
        List<KeystoreRecord> list = new ArrayList<>();
        try {
            SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            String jsonStr = sp.getString(KEY_KEYSTORES, "[]");
            JSONArray array = new JSONArray(jsonStr);
            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                int years = obj.optInt("validityYears", -1);
                if (years <= 0) {
                    int oldDays = obj.optInt("validityDays", 36500);
                    years = Math.max(1, Math.round(oldDays / 365f));
                }
                list.add(new KeystoreRecord(
                        obj.optString("fileName", ""),
                        obj.optString("format", "JKS"),
                        obj.optString("alias", ""),
                        years,
                        obj.optString("sha256", ""),
                        obj.optString("filePath", ""),
                        obj.optLong("timestamp", 0)
                ));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }

    public static void saveAabRecord(Context context, AabRecord record) {
        try {
            SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            String jsonStr = sp.getString(KEY_AAB, "[]");
            JSONArray array = new JSONArray(jsonStr);

            JSONObject obj = new JSONObject();
            obj.put("apkName", record.apkName);
            obj.put("aabName", record.aabName);
            obj.put("fileSize", record.fileSize);
            obj.put("signedKeyAlias", record.signedKeyAlias);
            obj.put("sha256", record.sha256);
            obj.put("filePath", record.filePath);
            obj.put("status", record.status);
            obj.put("timestamp", record.timestamp);

            JSONArray newArray = new JSONArray();
            newArray.put(obj);
            for (int i = 0; i < array.length() && i < 99; i++) {
                newArray.put(array.get(i));
            }
            sp.edit().putString(KEY_AAB, newArray.toString()).apply();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static List<AabRecord> getAabRecords(Context context) {
        List<AabRecord> list = new ArrayList<>();
        try {
            SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            String jsonStr = sp.getString(KEY_AAB, "[]");
            JSONArray array = new JSONArray(jsonStr);
            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                list.add(new AabRecord(
                        obj.optString("apkName", ""),
                        obj.optString("aabName", ""),
                        obj.optString("fileSize", ""),
                        obj.optString("signedKeyAlias", ""),
                        obj.optString("sha256", ""),
                        obj.optString("filePath", ""),
                        obj.optString("status", "Signed"),
                        obj.optLong("timestamp", 0)
                ));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }

    public static void clearHistory(Context context) {
        SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        sp.edit().clear().apply();
    }
}
