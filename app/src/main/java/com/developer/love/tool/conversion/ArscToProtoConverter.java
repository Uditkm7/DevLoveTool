package com.developer.love.tool.conversion;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parses Android binary resources.arsc (ResTable) and compiles it into aapt.pb.ResourceTable
 * Protocol Buffer format (base/resources.pb) required by Google Play and bundletool.
 */
public final class ArscToProtoConverter {

    public static class ConversionOutput {
        public byte[] resourcesPb;
        public int appPackageId = 0x7F;
        public final Map<Integer, String> resIdToName = new LinkedHashMap<>();
    }

    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int RES_TABLE_TYPE = 0x0002;
    private static final int RES_TABLE_PACKAGE_TYPE = 0x0200;
    private static final int RES_TABLE_TYPE_TYPE = 0x0201;
    private static final int RES_TABLE_TYPE_SPEC_TYPE = 0x0202;
    private static final int RES_TABLE_LIBRARY_TYPE = 0x0203;
    private static final int RES_TABLE_OVERLAYABLE_TYPE = 0x0204;

    private static final int FLAG_SPARSE = 0x01;
    private static final int FLAG_OFFSET16 = 0x02;

    private static final int ENTRY_FLAG_COMPLEX = 0x0001;
    private static final int ENTRY_FLAG_PUBLIC = 0x0002;
    private static final int ENTRY_FLAG_WEAK = 0x0004;
    private static final int ENTRY_FLAG_COMPACT = 0x0008;

    private static final int ATTR_TYPE = 0x01000000;
    private static final int ATTR_MIN = 0x01000001;
    private static final int ATTR_MAX = 0x01000002;
    private static final int ATTR_L10N = 0x01000003;
    private static final int ATTR_OTHER = 0x01000004;
    private static final int ATTR_ZERO = 0x01000005;
    private static final int ATTR_ONE = 0x01000006;
    private static final int ATTR_TWO = 0x01000007;
    private static final int ATTR_FEW = 0x01000008;
    private static final int ATTR_MANY = 0x01000009;

    private static class ParsedMapItem {
        int name;
        int dataType;
        int data;
    }

    private static class ParsedConfigValue {
        byte[] configBytes;
        int entryFlags;
        int dataType;
        int data;
        int parentResId;
        List<ParsedMapItem> mapItems;
    }

    private static class ParsedEntry {
        int entryId;
        String name;
        boolean isPublic;
        final List<ParsedConfigValue> configValues = new ArrayList<>();
    }

    private static class ParsedType {
        int typeId;
        String name;
        final Map<Integer, ParsedEntry> entries = new LinkedHashMap<>();
    }

    private static class ParsedPackage {
        int packageId;
        String packageName;
        final Map<Integer, ParsedType> types = new LinkedHashMap<>();
    }

    private static class DynamicLibEntry {
        int packageId;
        String packageName;
    }

    private static class OverlayableDecl {
        String name;
        String actor;
    }

    private ArscToProtoConverter() {}

    public static ConversionOutput convert(
            byte[] arscBytes,
            Set<String> xmlResEntries,
            Set<String> allApkEntries
    ) {
        if (arscBytes == null || arscBytes.length < 12) {
            throw new IllegalArgumentException("Invalid resources.arsc data.");
        }

        ByteBuffer buf = ByteBuffer.wrap(arscBytes).order(ByteOrder.LITTLE_ENDIAN);
        int rootType = buf.getShort(0) & 0xFFFF;
        int rootHeaderSize = buf.getShort(2) & 0xFFFF;
        int totalSize = Math.min(buf.getInt(4), arscBytes.length);

        if (rootType != RES_TABLE_TYPE) {
            throw new IllegalArgumentException("Expected RES_TABLE_TYPE (0x0002), got 0x" + Integer.toHexString(rootType));
        }

        ConversionOutput out = new ConversionOutput();
        ResStringPoolReader globalStrings = null;
        List<ParsedPackage> packages = new ArrayList<>();
        List<DynamicLibEntry> dynamicLibs = new ArrayList<>();
        List<OverlayableDecl> overlayables = new ArrayList<>();

        int pos = rootHeaderSize;
        while (pos + 8 <= totalSize) {
            int chunkType = buf.getShort(pos) & 0xFFFF;
            int chunkSize = buf.getInt(pos + 4);
            if (chunkSize <= 0 || pos + chunkSize > totalSize) break;

            if (chunkType == RES_STRING_POOL_TYPE) {
                globalStrings = ResStringPoolReader.parse(arscBytes, pos);
            } else if (chunkType == RES_TABLE_PACKAGE_TYPE) {
                ParsedPackage pkg = parsePackage(arscBytes, buf, pos, pos + chunkSize, dynamicLibs, overlayables, out.resIdToName);
                packages.add(pkg);
                if (pkg.packageId >= 0x7F) {
                    out.appPackageId = pkg.packageId;
                }
            }
            pos += chunkSize;
        }

        // Encode ResourceTable protobuf
        ProtoWriter tableW = new ProtoWriter();
        for (ParsedPackage pkg : packages) {
            tableW.writeMessageAlways(2, encodePackage(pkg, globalStrings, out.resIdToName, xmlResEntries, allApkEntries));
        }
        for (OverlayableDecl ov : overlayables) {
            ProtoWriter ovW = new ProtoWriter();
            ovW.writeString(1, ov.name);
            ovW.writeString(3, ov.actor);
            tableW.writeMessageAlways(3, ovW.toByteArray());
        }
        ProtoWriter tfW = new ProtoWriter();
        tfW.writeString(1, "DevLoveTool");
        tfW.writeString(2, "1.0");
        tableW.writeMessageAlways(4, tfW.toByteArray());

        for (DynamicLibEntry lib : dynamicLibs) {
            ProtoWriter libW = new ProtoWriter();
            ProtoWriter pidW = new ProtoWriter();
            pidW.writeUInt32Always(1, lib.packageId);
            libW.writeMessageAlways(1, pidW.toByteArray());
            libW.writeString(2, lib.packageName);
            tableW.writeMessageAlways(5, libW.toByteArray());
        }

        out.resourcesPb = tableW.toByteArray();
        return out;
    }

    private static ParsedPackage parsePackage(
            byte[] data,
            ByteBuffer buf,
            int pkgStart,
            int pkgEnd,
            List<DynamicLibEntry> dynamicLibs,
            List<OverlayableDecl> overlayables,
            Map<Integer, String> resIdToName
    ) {
        int headerSize = buf.getShort(pkgStart + 2) & 0xFFFF;
        if (headerSize < 284 || pkgStart + headerSize > pkgEnd) {
            throw new IllegalArgumentException("Invalid ResTable_package header size: " + headerSize);
        }
        int pkgId = buf.getInt(pkgStart + 8);
        String pkgName = readUtf16Fixed(data, pkgStart + 12, 128);
        int typeStringsRel = buf.getInt(pkgStart + 268);
        int keyStringsRel = buf.getInt(pkgStart + 276);
        int typeIdOffset = headerSize >= 288 ? buf.getInt(pkgStart + 284) : 0;

        ResStringPoolReader typeStrings = (typeStringsRel > 0 && pkgStart + typeStringsRel + 28 <= pkgEnd)
                ? ResStringPoolReader.parse(data, pkgStart + typeStringsRel)
                : null;
        ResStringPoolReader keyStrings = (keyStringsRel > 0 && pkgStart + keyStringsRel + 28 <= pkgEnd)
                ? ResStringPoolReader.parse(data, pkgStart + keyStringsRel)
                : null;

        ParsedPackage pkg = new ParsedPackage();
        pkg.packageId = pkgId;
        pkg.packageName = pkgName;

        int pos = pkgStart + headerSize;
        while (pos + 8 <= pkgEnd) {
            int chunkType = buf.getShort(pos) & 0xFFFF;
            int chunkHeaderSize = buf.getShort(pos + 2) & 0xFFFF;
            int chunkSize = buf.getInt(pos + 4);
            if (chunkHeaderSize < 8 || chunkSize < chunkHeaderSize || pos + chunkSize > pkgEnd) break;

            if (chunkType == RES_TABLE_TYPE_SPEC_TYPE) {
                int typeId = buf.get(pos + 8) & 0xFF;
                if (typeId > 0) {
                    ensureType(pkg, typeId, typeIdOffset, typeStrings);
                }
            } else if (chunkType == RES_TABLE_TYPE_TYPE) {
                if (pos + 24 > pos + chunkSize) {
                    pos += chunkSize;
                    continue;
                }
                int typeId = buf.get(pos + 8) & 0xFF;
                int typeFlags = buf.get(pos + 9) & 0xFF;
                int entryCount = buf.getInt(pos + 12);
                int entriesStart = buf.getInt(pos + 16);
                if (typeId <= 0 || entryCount < 0 || entryCount > 1_000_000) {
                    pos += chunkSize;
                    continue;
                }
                int cfgPos = pos + 20;
                int cfgSize = (cfgPos + 4 <= pos + chunkHeaderSize)
                        ? Math.min(buf.getInt(cfgPos), (pos + chunkHeaderSize) - cfgPos)
                        : 0;
                if (cfgSize < 0) cfgSize = 0;
                byte[] cfgBytes = new byte[cfgSize];
                if (cfgSize > 0) {
                    System.arraycopy(data, cfgPos, cfgBytes, 0, cfgSize);
                }

                ParsedType parsedType = ensureType(pkg, typeId, typeIdOffset, typeStrings);
                boolean isSparse = (typeFlags & FLAG_SPARSE) != 0;
                boolean isOffset16 = (typeFlags & FLAG_OFFSET16) != 0;
                int offsetsBase = pos + chunkHeaderSize;
                int entriesBase = pos + entriesStart;

                for (int i = 0; i < entryCount; i++) {
                    int entryId;
                    int relOffset;
                    if (isSparse) {
                        int p = offsetsBase + i * 4;
                        if (p + 4 > pos + chunkSize) break;
                        entryId = buf.getShort(p) & 0xFFFF;
                        relOffset = (buf.getShort(p + 2) & 0xFFFF) * 4;
                    } else if (isOffset16) {
                        int p = offsetsBase + i * 2;
                        if (p + 2 > pos + chunkSize) break;
                        int off16 = buf.getShort(p) & 0xFFFF;
                        if (off16 == 0xFFFF) continue;
                        entryId = i;
                        relOffset = off16 * 4;
                    } else {
                        int p = offsetsBase + i * 4;
                        if (p + 4 > pos + chunkSize) break;
                        int off32 = buf.getInt(p);
                        if (off32 == 0xFFFFFFFF) continue;
                        entryId = i;
                        relOffset = off32;
                    }

                    int ePos = entriesBase + relOffset;
                    if (ePos + 8 > pos + chunkSize) continue;

                    int eSize = buf.getShort(ePos) & 0xFFFF;
                    int eFlags = buf.getShort(ePos + 2) & 0xFFFF;
                    boolean isCompact = (eFlags & ENTRY_FLAG_COMPACT) != 0;
                    boolean isComplex = !isCompact && (eFlags & ENTRY_FLAG_COMPLEX) != 0;
                    boolean isPublic = (eFlags & ENTRY_FLAG_PUBLIC) != 0;

                    int keyIdx = isCompact ? eSize : buf.getInt(ePos + 4);
                    String entryName = keyStrings != null ? keyStrings.getString(keyIdx) : ("res_" + entryId);
                    if (entryName == null) entryName = "res_" + entryId;

                    int fullResId = (pkgId << 24) | (typeId << 16) | entryId;
                    resIdToName.put(fullResId, pkgName + ":" + parsedType.name + "/" + entryName);

                    ParsedEntry entry = parsedType.entries.get(entryId);
                    if (entry == null) {
                        entry = new ParsedEntry();
                        entry.entryId = entryId;
                        entry.name = entryName;
                        parsedType.entries.put(entryId, entry);
                    }
                    if (isPublic) entry.isPublic = true;

                    ParsedConfigValue cv = new ParsedConfigValue();
                    cv.configBytes = cfgBytes;
                    cv.entryFlags = eFlags;

                    if (isCompact) {
                        cv.dataType = (eFlags >>> 8) & 0xFF;
                        cv.data = buf.getInt(ePos + 4);
                    } else if (isComplex) {
                        if (ePos + 16 > pos + chunkSize) continue;
                        cv.parentResId = buf.getInt(ePos + 8);
                        int mapCount = buf.getInt(ePos + 12);
                        cv.mapItems = new ArrayList<>(Math.max(0, Math.min(mapCount, 1024)));
                        int mPos = ePos + eSize;
                        for (int m = 0; m < mapCount; m++) {
                            if (mPos + 12 > pos + chunkSize) break;
                            ParsedMapItem mi = new ParsedMapItem();
                            mi.name = buf.getInt(mPos);
                            mi.dataType = buf.get(mPos + 7) & 0xFF;
                            mi.data = buf.getInt(mPos + 8);
                            cv.mapItems.add(mi);
                            mPos += 12;
                        }
                    } else {
                        int vPos = ePos + eSize;
                        if (vPos + 8 > pos + chunkSize) continue;
                        cv.dataType = buf.get(vPos + 3) & 0xFF;
                        cv.data = buf.getInt(vPos + 4);
                    }
                    entry.configValues.add(cv);
                }
            } else if (chunkType == RES_TABLE_LIBRARY_TYPE) {
                int count = buf.getInt(pos + 8);
                int lPos = pos + chunkHeaderSize;
                for (int i = 0; i < count; i++) {
                    if (lPos + 260 > pos + chunkSize) break;
                    DynamicLibEntry d = new DynamicLibEntry();
                    d.packageId = buf.getInt(lPos);
                    d.packageName = readUtf16Fixed(data, lPos + 4, 128);
                    dynamicLibs.add(d);
                    lPos += 260;
                }
            } else if (chunkType == RES_TABLE_OVERLAYABLE_TYPE) {
                if (pos + 8 + 1024 <= pos + chunkSize) {
                    OverlayableDecl ov = new OverlayableDecl();
                    ov.name = readUtf16Fixed(data, pos + 8, 256);
                    ov.actor = readUtf16Fixed(data, pos + 8 + 512, 256);
                    overlayables.add(ov);
                }
            }
            pos += chunkSize;
        }

        return pkg;
    }

    private static ParsedType ensureType(ParsedPackage pkg, int typeId, int typeIdOffset, ResStringPoolReader typeStrings) {
        ParsedType pt = pkg.types.get(typeId);
        if (pt == null) {
            pt = new ParsedType();
            pt.typeId = typeId;
            String tName = null;
            if (typeStrings != null) {
                int idx = typeId - 1 - typeIdOffset;
                tName = typeStrings.getString(idx);
                if (tName == null && typeIdOffset != 0) {
                    tName = typeStrings.getString(typeId - 1);
                }
            }
            pt.name = (tName != null && !tName.isEmpty()) ? tName : ("type_" + typeId);
            pkg.types.put(typeId, pt);
        }
        return pt;
    }

    private static byte[] encodePackage(
            ParsedPackage pkg,
            ResStringPoolReader globalStrings,
            Map<Integer, String> resIdToName,
            Set<String> xmlResEntries,
            Set<String> allApkEntries
    ) {
        ProtoWriter pkgW = new ProtoWriter();
        ProtoWriter pidW = new ProtoWriter();
        pidW.writeUInt32Always(1, pkg.packageId);
        pkgW.writeMessageAlways(1, pidW.toByteArray());
        pkgW.writeString(2, pkg.packageName);

        for (ParsedType type : pkg.types.values()) {
            ProtoWriter typeW = new ProtoWriter();
            ProtoWriter tidW = new ProtoWriter();
            tidW.writeUInt32Always(1, type.typeId);
            typeW.writeMessageAlways(1, tidW.toByteArray());
            typeW.writeString(2, type.name);

            for (ParsedEntry entry : type.entries.values()) {
                ProtoWriter entryW = new ProtoWriter();
                ProtoWriter eidW = new ProtoWriter();
                eidW.writeUInt32Always(1, entry.entryId);
                entryW.writeMessageAlways(1, eidW.toByteArray());
                entryW.writeString(2, entry.name);

                if (entry.isPublic) {
                    ProtoWriter visW = new ProtoWriter();
                    visW.writeEnum(1, 2); // PUBLIC
                    entryW.writeMessageAlways(3, visW.toByteArray());
                }

                for (ParsedConfigValue cv : entry.configValues) {
                    ProtoWriter cvW = new ProtoWriter();
                    byte[] cfgProto = encodeConfiguration(cv.configBytes);
                    cvW.writeMessageAlways(1, cfgProto);

                    ProtoWriter valW = new ProtoWriter();
                    if ((cv.entryFlags & ENTRY_FLAG_WEAK) != 0) {
                        valW.writeBool(3, true);
                    }

                    boolean isComplex = (cv.entryFlags & ENTRY_FLAG_COMPACT) == 0
                            && (cv.entryFlags & ENTRY_FLAG_COMPLEX) != 0;
                    if (isComplex) {
                        byte[] compBytes = encodeCompoundValue(
                                type.name, cv, globalStrings, pkg.packageId, resIdToName, xmlResEntries, allApkEntries
                        );
                        valW.writeMessageAlways(5, compBytes);
                    } else {
                        byte[] itemBytes = ResItemProtoEncoder.encodeItem(
                                cv.dataType, cv.data, type.name, globalStrings, pkg.packageId, resIdToName, xmlResEntries, allApkEntries
                        );
                        valW.writeMessageAlways(4, itemBytes);
                    }

                    cvW.writeMessageAlways(2, valW.toByteArray());
                    entryW.writeMessageAlways(6, cvW.toByteArray());
                }

                typeW.writeMessageAlways(3, entryW.toByteArray());
            }

            pkgW.writeMessageAlways(3, typeW.toByteArray());
        }

        return pkgW.toByteArray();
    }

    private static byte[] encodeCompoundValue(
            String typeName,
            ParsedConfigValue cv,
            ResStringPoolReader globalStrings,
            int pkgId,
            Map<Integer, String> resIdToName,
            Set<String> xmlResEntries,
            Set<String> allApkEntries
    ) {
        ProtoWriter comp = new ProtoWriter();
        List<ParsedMapItem> items = cv.mapItems != null ? cv.mapItems : new ArrayList<>();

        if ("attr".equals(typeName) || "^attr-private".equals(typeName)) {
            ProtoWriter attrW = new ProtoWriter();
            int formatFlags = 0x0000FFFF;
            int minInt = 0;
            int maxInt = 0;
            boolean hasMin = false;
            boolean hasMax = false;
            List<ParsedMapItem> symbols = new ArrayList<>();

            for (ParsedMapItem mi : items) {
                if (mi.name == ATTR_TYPE) {
                    formatFlags = mi.data;
                } else if (mi.name == ATTR_MIN) {
                    minInt = mi.data;
                    hasMin = true;
                } else if (mi.name == ATTR_MAX) {
                    maxInt = mi.data;
                    hasMax = true;
                } else if (mi.name == ATTR_L10N) {
                    // localization flag - ignored in proto Attribute
                } else {
                    symbols.add(mi);
                }
            }

            attrW.writeUInt32(1, formatFlags);
            if (hasMin) attrW.writeInt32Always(2, minInt);
            if (hasMax) attrW.writeInt32Always(3, maxInt);

            for (ParsedMapItem sym : symbols) {
                ProtoWriter symW = new ProtoWriter();
                byte[] refBytes = ResItemProtoEncoder.encodeReference(0, sym.name, pkgId, resIdToName);
                symW.writeMessageAlways(3, refBytes);
                symW.writeUInt32Always(4, sym.data);
                symW.writeUInt32Always(5, sym.dataType);
                attrW.writeMessageAlways(4, symW.toByteArray());
            }
            comp.writeMessageAlways(1, attrW.toByteArray());
        } else if ("plurals".equals(typeName)) {
            ProtoWriter plW = new ProtoWriter();
            for (ParsedMapItem mi : items) {
                int arity = mapPluralArity(mi.name);
                if (arity < 0) continue;
                ProtoWriter peW = new ProtoWriter();
                if (arity != 0) {
                    peW.writeEnum(3, arity);
                } else {
                    peW.writeUInt32Always(3, 0);
                }
                peW.writeMessageAlways(4, ResItemProtoEncoder.encodeItem(
                        mi.dataType, mi.data, "string", globalStrings, pkgId, resIdToName, xmlResEntries, allApkEntries
                ));
                plW.writeMessageAlways(1, peW.toByteArray());
            }
            comp.writeMessageAlways(5, plW.toByteArray());
        } else if ("array".equals(typeName)) {
            ProtoWriter arrW = new ProtoWriter();
            for (ParsedMapItem mi : items) {
                ProtoWriter elW = new ProtoWriter();
                elW.writeMessageAlways(3, ResItemProtoEncoder.encodeItem(
                        mi.dataType, mi.data, null, globalStrings, pkgId, resIdToName, xmlResEntries, allApkEntries
                ));
                arrW.writeMessageAlways(1, elW.toByteArray());
            }
            comp.writeMessageAlways(4, arrW.toByteArray());
        } else {
            // style (or other map bag)
            ProtoWriter stW = new ProtoWriter();
            if (cv.parentResId != 0) {
                stW.writeMessageAlways(1, ResItemProtoEncoder.encodeReference(0, cv.parentResId, pkgId, resIdToName));
            }
            for (ParsedMapItem mi : items) {
                ProtoWriter seW = new ProtoWriter();
                seW.writeMessageAlways(3, ResItemProtoEncoder.encodeReference(0, mi.name, pkgId, resIdToName));
                seW.writeMessageAlways(4, ResItemProtoEncoder.encodeItem(
                        mi.dataType, mi.data, null, globalStrings, pkgId, resIdToName, xmlResEntries, allApkEntries
                ));
                stW.writeMessageAlways(3, seW.toByteArray());
            }
            comp.writeMessageAlways(2, stW.toByteArray());
        }
        return comp.toByteArray();
    }

    private static int mapPluralArity(int attrName) {
        switch (attrName) {
            case ATTR_ZERO: return 0;
            case ATTR_ONE: return 1;
            case ATTR_TWO: return 2;
            case ATTR_FEW: return 3;
            case ATTR_MANY: return 4;
            case ATTR_OTHER: return 5;
            default: return -1;
        }
    }

    private static byte[] encodeConfiguration(byte[] cfg) {
        ProtoWriter w = new ProtoWriter();
        if (cfg == null || cfg.length < 4) return w.toByteArray();

        ByteBuffer b = ByteBuffer.wrap(cfg).order(ByteOrder.LITTLE_ENDIAN);
        int size = cfg.length;

        int mcc = size >= 6 ? (b.getShort(4) & 0xFFFF) : 0;
        int mnc = size >= 8 ? (b.getShort(6) & 0xFFFF) : 0;
        w.writeUInt32(1, mcc);
        w.writeUInt32(2, mnc);

        String lang = size >= 10 ? unpackLangOrRegion(cfg, 8, 'a') : "";
        String region = size >= 12 ? unpackLangOrRegion(cfg, 10, '0') : "";
        String script = size >= 40 ? readAsciiFixed(cfg, 36, 4) : "";
        String variant = size >= 48 ? readAsciiFixed(cfg, 40, 8) : "";
        String locale = buildBcp47Locale(lang, script, region, variant);
        w.writeString(3, locale);

        if (size >= 29) {
            int screenLayout = cfg[28] & 0xFF;
            int layoutDir = (screenLayout >>> 6) & 0x03; // 0=unset, 1=LTR, 2=RTL
            w.writeEnum(4, layoutDir);
        }

        if (size >= 24) {
            w.writeUInt32(5, b.getShort(20) & 0xFFFF); // screenWidth
            w.writeUInt32(6, b.getShort(22) & 0xFFFF); // screenHeight
        }
        if (size >= 36) {
            w.writeUInt32(7, b.getShort(32) & 0xFFFF); // screenWidthDp
            w.writeUInt32(8, b.getShort(34) & 0xFFFF); // screenHeightDp
        }
        if (size >= 32) {
            w.writeUInt32(9, b.getShort(30) & 0xFFFF); // smallestScreenWidthDp
        }

        if (size >= 29) {
            int screenLayout = cfg[28] & 0xFF;
            w.writeEnum(10, screenLayout & 0x0F); // screen_layout_size
            int slLong = (screenLayout >>> 4) & 0x03;
            if (slLong == 1) w.writeEnum(11, 2); // NOTLONG
            else if (slLong == 2) w.writeEnum(11, 1); // LONG
        }

        if (size >= 50) {
            int screenLayout2 = cfg[48] & 0xFF;
            int slRound = screenLayout2 & 0x03;
            if (slRound == 1) w.writeEnum(12, 2); // NOTROUND
            else if (slRound == 2) w.writeEnum(12, 1); // ROUND

            int colorMode = cfg[49] & 0xFF;
            int wcg = colorMode & 0x03;
            if (wcg == 1) w.writeEnum(13, 2); // NOWIDECG
            else if (wcg == 2) w.writeEnum(13, 1); // WIDECG

            int hdr = (colorMode >>> 2) & 0x03;
            if (hdr == 1) w.writeEnum(14, 2); // LOWDR
            else if (hdr == 2) w.writeEnum(14, 1); // HIGHDR
        }

        if (size >= 16) {
            w.writeEnum(15, cfg[12] & 0xFF); // orientation
        }
        if (size >= 30) {
            int uiMode = cfg[29] & 0xFF;
            w.writeEnum(16, uiMode & 0x0F); // ui_mode_type
            int uiNight = (uiMode >>> 4) & 0x03;
            if (uiNight == 1) w.writeEnum(17, 2); // NOTNIGHT
            else if (uiNight == 2) w.writeEnum(17, 1); // NIGHT
        }
        if (size >= 16) {
            w.writeUInt32(18, b.getShort(14) & 0xFFFF); // density
        }
        if (size >= 19) {
            w.writeEnum(19, cfg[13] & 0xFF); // touchscreen
            int inputFlags = cfg[18] & 0xFF;
            w.writeEnum(20, inputFlags & 0x03); // keys_hidden
            w.writeEnum(21, cfg[16] & 0xFF); // keyboard
            w.writeEnum(22, (inputFlags >>> 2) & 0x03); // nav_hidden
            w.writeEnum(23, cfg[17] & 0xFF); // navigation
        }
        if (size >= 26) {
            w.writeUInt32(24, b.getShort(24) & 0xFFFF); // sdkVersion
        }
        if (size >= 56) {
            int gender = cfg[19] & 0x03;
            w.writeEnum(26, gender);
        }

        return w.toByteArray();
    }

    private static String unpackLangOrRegion(byte[] buf, int offset, char base) {
        int b0 = buf[offset] & 0xFF;
        int b1 = buf[offset + 1] & 0xFF;
        if (b0 == 0 && b1 == 0) return "";
        if ((b0 & 0x80) != 0) {
            int first = b1 & 0x1F;
            int second = ((b1 & 0xE0) >>> 5) | ((b0 & 0x03) << 3);
            int third = (b0 & 0x7C) >>> 2;
            char c0 = (char) (base + first);
            char c1 = (char) (base + second);
            char c2 = (char) (base + third);
            return new String(new char[]{c0, c1, c2});
        }
        StringBuilder sb = new StringBuilder(2);
        if (b0 != 0) sb.append((char) b0);
        if (b1 != 0) sb.append((char) b1);
        return sb.toString();
    }

    private static String buildBcp47Locale(String lang, String script, String region, String variant) {
        if (lang.isEmpty() && region.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        if (!lang.isEmpty()) sb.append(lang);
        if (!script.isEmpty()) {
            if (sb.length() > 0) sb.append('-');
            sb.append(script);
        }
        if (!region.isEmpty()) {
            if (sb.length() > 0) sb.append('-');
            sb.append(region);
        }
        if (!variant.isEmpty()) {
            if (sb.length() > 0) sb.append('-');
            sb.append(variant);
        }
        return sb.toString();
    }

    private static String readUtf16Fixed(byte[] data, int offset, int maxChars) {
        int len = 0;
        while (len < maxChars && offset + len * 2 + 1 < data.length) {
            int ch = (data[offset + len * 2] & 0xFF) | ((data[offset + len * 2 + 1] & 0xFF) << 8);
            if (ch == 0) break;
            len++;
        }
        return new String(data, offset, len * 2, StandardCharsets.UTF_16LE);
    }

    private static String readAsciiFixed(byte[] data, int offset, int maxBytes) {
        int len = 0;
        while (len < maxBytes && offset + len < data.length && data[offset + len] != 0) {
            len++;
        }
        return len > 0 ? new String(data, offset, len, StandardCharsets.US_ASCII) : "";
    }
}
