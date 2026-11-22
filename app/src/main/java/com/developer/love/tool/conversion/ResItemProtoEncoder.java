package com.developer.love.tool.conversion;

import android.content.res.Resources;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Encodes Android Res_value items into aapt.pb.Item protobuf wire format.
 */
public final class ResItemProtoEncoder {

    public static final int TYPE_NULL = 0x00;
    public static final int TYPE_REFERENCE = 0x01;
    public static final int TYPE_ATTRIBUTE = 0x02;
    public static final int TYPE_STRING = 0x03;
    public static final int TYPE_FLOAT = 0x04;
    public static final int TYPE_DIMENSION = 0x05;
    public static final int TYPE_FRACTION = 0x06;
    public static final int TYPE_DYNAMIC_REFERENCE = 0x07;
    public static final int TYPE_DYNAMIC_ATTRIBUTE = 0x08;
    public static final int TYPE_INT_DEC = 0x10;
    public static final int TYPE_INT_HEX = 0x11;
    public static final int TYPE_INT_BOOLEAN = 0x12;
    public static final int TYPE_INT_COLOR_ARGB8 = 0x1C;
    public static final int TYPE_INT_COLOR_RGB8 = 0x1D;
    public static final int TYPE_INT_COLOR_ARGB4 = 0x1E;
    public static final int TYPE_INT_COLOR_RGB4 = 0x1F;

    private ResItemProtoEncoder() {}

    public static String resolveResourceName(int resId, int currentPkgId, Map<Integer, String> localResMap) {
        if (resId == 0) return null;
        if (localResMap != null) {
            String name = localResMap.get(resId);
            if (name != null) {
                int pkgId = (resId >>> 24) & 0xFF;
                if (pkgId == currentPkgId && name.contains(":")) {
                    return name.substring(name.indexOf(':') + 1);
                }
                return name;
            }
        }
        int pkgId = (resId >>> 24) & 0xFF;
        if (pkgId == 0x01) {
            try {
                // Returns e.g. "android:attr/name" or "android:style/Theme"
                return Resources.getSystem().getResourceName(resId);
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    public static byte[] encodeReference(int resType, int resId, int currentPkgId, Map<Integer, String> localResMap) {
        ProtoWriter ref = new ProtoWriter();
        if (resType != 0) {
            ref.writeEnum(1, resType); // 0=REFERENCE, 1=ATTRIBUTE
        }
        if (resId != 0) {
            ref.writeUInt32Always(2, resId);
        }
        String name = resolveResourceName(resId, currentPkgId, localResMap);
        if (name != null && !name.isEmpty()) {
            ref.writeString(3, name);
        }
        return ref.toByteArray();
    }

    public static byte[] encodeItem(
            int dataType,
            int data,
            String typeName,
            ResStringPoolReader stringPool,
            int currentPkgId,
            Map<Integer, String> localResMap,
            Set<String> xmlResEntries,
            Set<String> allApkEntries
    ) {
        ProtoWriter item = new ProtoWriter();
        switch (dataType) {
            case TYPE_NULL: {
                if ("id".equals(typeName)) {
                    item.writeEmptyMessage(6); // Item.id
                } else {
                    ProtoWriter prim = new ProtoWriter();
                    if (data == 1) {
                        prim.writeEmptyMessage(2); // empty_value
                    } else {
                        prim.writeEmptyMessage(1); // null_value
                    }
                    item.writeMessageAlways(7, prim.toByteArray());
                }
                break;
            }
            case TYPE_REFERENCE:
            case TYPE_DYNAMIC_REFERENCE: {
                byte[] refBytes = encodeReference(0, data, currentPkgId, localResMap);
                item.writeMessageAlways(1, refBytes);
                break;
            }
            case TYPE_ATTRIBUTE:
            case TYPE_DYNAMIC_ATTRIBUTE: {
                byte[] refBytes = encodeReference(1, data, currentPkgId, localResMap);
                item.writeMessageAlways(1, refBytes);
                break;
            }
            case TYPE_STRING: {
                String s = stringPool != null ? stringPool.getString(data) : "";
                if (s == null) s = "";
                boolean isFileRef = typeName != null
                        && !"string".equals(typeName)
                        && !"id".equals(typeName)
                        && s.startsWith("res/")
                        && (allApkEntries == null || allApkEntries.contains(s));
                if (isFileRef) {
                    ProtoWriter fr = new ProtoWriter();
                    fr.writeString(1, s);
                    int fileType = 0; // UNKNOWN
                    if (xmlResEntries != null && xmlResEntries.contains(s)) {
                        fileType = 3; // PROTO_XML
                    } else if (s.toLowerCase(Locale.US).endsWith(".png")) {
                        fileType = 1; // PNG
                    }
                    fr.writeEnum(2, fileType);
                    item.writeMessageAlways(5, fr.toByteArray());
                } else {
                    List<ResStringPoolReader.Span> spans = stringPool != null ? stringPool.getSpans(data) : null;
                    if (spans != null && !spans.isEmpty()) {
                        ProtoWriter ss = new ProtoWriter();
                        ss.writeString(1, s);
                        for (ResStringPoolReader.Span sp : spans) {
                            ProtoWriter spW = new ProtoWriter();
                            spW.writeString(1, sp.tag);
                            spW.writeUInt32Always(2, sp.firstChar);
                            spW.writeUInt32Always(3, sp.lastChar);
                            ss.writeMessageAlways(2, spW.toByteArray());
                        }
                        item.writeMessageAlways(4, ss.toByteArray());
                    } else {
                        ProtoWriter strW = new ProtoWriter();
                        strW.writeString(1, s);
                        item.writeMessageAlways(2, strW.toByteArray());
                    }
                }
                break;
            }
            case TYPE_FLOAT: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeFloatAlways(3, Float.intBitsToFloat(data));
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
            case TYPE_DIMENSION: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeUInt32Always(13, data);
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
            case TYPE_FRACTION: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeUInt32Always(14, data);
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
            case TYPE_INT_DEC: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeInt32Always(6, data);
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
            case TYPE_INT_HEX: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeUInt32Always(7, data);
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
            case TYPE_INT_BOOLEAN: {
                if ("id".equals(typeName) && data == 0) {
                    item.writeEmptyMessage(6); // aapt2 encodes <item type="id"> in .arsc as TYPE_INT_BOOLEAN(0)
                } else {
                    ProtoWriter prim = new ProtoWriter();
                    prim.writeTag(8, ProtoWriter.WIRE_VARINT);
                    prim.writeRawVarint32(data != 0 ? 1 : 0);
                    item.writeMessageAlways(7, prim.toByteArray());
                }
                break;
            }
            case TYPE_INT_COLOR_ARGB8: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeUInt32Always(9, data);
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
            case TYPE_INT_COLOR_RGB8: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeUInt32Always(10, data);
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
            case TYPE_INT_COLOR_ARGB4: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeUInt32Always(11, data);
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
            case TYPE_INT_COLOR_RGB4: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeUInt32Always(12, data);
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
            default: {
                ProtoWriter prim = new ProtoWriter();
                prim.writeInt32Always(6, data);
                item.writeMessageAlways(7, prim.toByteArray());
                break;
            }
        }
        return item.toByteArray();
    }

    public static String formatAttributeDisplayValue(
            int dataType,
            int data,
            String rawStr,
            ResStringPoolReader stringPool,
            int currentPkgId,
            Map<Integer, String> localResMap
    ) {
        if (rawStr != null) return rawStr;
        switch (dataType) {
            case TYPE_NULL:
                return data == 1 ? "@empty" : "@null";
            case TYPE_REFERENCE:
            case TYPE_DYNAMIC_REFERENCE: {
                if (data == 0) return "@null";
                String name = resolveResourceName(data, currentPkgId, localResMap);
                return name != null ? "@" + name : String.format(Locale.US, "@0x%08x", data);
            }
            case TYPE_ATTRIBUTE:
            case TYPE_DYNAMIC_ATTRIBUTE: {
                String name = resolveResourceName(data, currentPkgId, localResMap);
                return name != null ? "?" + name : String.format(Locale.US, "?0x%08x", data);
            }
            case TYPE_STRING: {
                String s = stringPool != null ? stringPool.getString(data) : "";
                return s != null ? s : "";
            }
            case TYPE_FLOAT:
                return Float.toString(Float.intBitsToFloat(data));
            case TYPE_DIMENSION:
                return formatComplexDimension(data);
            case TYPE_FRACTION:
                return formatComplexFraction(data);
            case TYPE_INT_DEC:
                return Integer.toString(data);
            case TYPE_INT_HEX:
                return String.format(Locale.US, "0x%x", data);
            case TYPE_INT_BOOLEAN:
                return data != 0 ? "true" : "false";
            case TYPE_INT_COLOR_ARGB8:
            case TYPE_INT_COLOR_RGB8:
            case TYPE_INT_COLOR_ARGB4:
            case TYPE_INT_COLOR_RGB4:
                return String.format(Locale.US, "#%08x", data);
            default:
                return String.format(Locale.US, "0x%08x", data);
        }
    }

    private static float decodeComplexFloat(int data) {
        int mantissa = data >> 8;
        int radix = (data >> 4) & 0x03;
        switch (radix) {
            case 0: return mantissa;
            case 1: return mantissa * (1.0f / (1 << 7));
            case 2: return mantissa * (1.0f / (1 << 15));
            case 3: return mantissa * (1.0f / (1 << 23));
            default: return mantissa;
        }
    }

    private static String formatComplexDimension(int data) {
        float val = decodeComplexFloat(data);
        String[] units = {"px", "dp", "sp", "pt", "in", "mm"};
        int unit = data & 0x0F;
        String unitStr = unit < units.length ? units[unit] : ("unit" + unit);
        return trimTrailingZeros(val) + unitStr;
    }

    private static String formatComplexFraction(int data) {
        float val = decodeComplexFloat(data) * 100.0f;
        int unit = data & 0x0F;
        String unitStr = unit == 1 ? "%p" : "%";
        return trimTrailingZeros(val) + unitStr;
    }

    private static String trimTrailingZeros(float v) {
        if (v == (long) v) {
            return Long.toString((long) v);
        }
        return Float.toString(v);
    }
}
