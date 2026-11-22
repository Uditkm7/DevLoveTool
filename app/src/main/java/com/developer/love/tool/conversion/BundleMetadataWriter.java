package com.developer.love.tool.conversion;

import java.util.Locale;
import java.util.Set;

/**
 * Generates standard Android App Bundle Protocol Buffer metadata files:
 * - BundleConfig.pb (android.bundle.BundleConfig)
 * - base/native.pb (android.bundle.NativeLibraries)
 * - base/assets.pb (android.bundle.Assets)
 */
public final class BundleMetadataWriter {

    private static final String[] DEFAULT_UNCOMPRESSED_GLOBS = {
            "**.3[gG]2", "**.3[gG][pP]", "**.3[gG][pP][pP]", "**.3[gG][pP][pP]2",
            "**.[aA][aA][cC]", "**.[aA][mM][rR]", "**.[aA][wW][bB]", "**.[gG][iI][fF]",
            "**.[iI][mM][yY]", "**.[jJ][eE][tT]", "**.[jJ][pP][eE][gG]", "**.[jJ][pP][gG]",
            "**.[mM]4[aA]", "**.[mM]4[vV]", "**.[mM][iI][dD]", "**.[mM][iI][dD][iI]",
            "**.[mM][kK][vV]", "**.[mM][pP]2", "**.[mM][pP]3", "**.[mM][pP]4",
            "**.[mM][pP][eE][gG]", "**.[mM][pP][gG]", "**.[oO][gG][gG]", "**.[oO][pP][uU][sS]",
            "**.[pP][nN][gG]", "**.[rR][tT][tT][tT][lL]", "**.[sS][mM][fF]", "**.[tT][fF][lL][iI][tT][eE]",
            "**.[wW][aA][vV]", "**.[wW][eE][bB][mM]", "**.[wW][eE][bB][pP]", "**.[wW][mM][aA]",
            "**.[wW][mM][vV]", "**.[xX][mM][fF]"
    };

    private BundleMetadataWriter() {}

    public static byte[] buildBundleConfigPb() {
        ProtoWriter config = new ProtoWriter();

        // 1. Bundletool version (match modern bundletool schema)
        ProtoWriter bt = new ProtoWriter();
        bt.writeString(2, "1.18.3");
        config.writeMessageAlways(1, bt.toByteArray());

        // 2. Optimizations
        ProtoWriter opt = new ProtoWriter();

        // splits_config = {} (empty SplitsConfig enables default ABI, SCREEN_DENSITY, LANGUAGE splits)
        opt.writeEmptyMessage(1);

        // uncompress_native_libraries = { enabled: true, alignment: PAGE_ALIGNMENT_16K (2) }
        ProtoWriter uncompLib = new ProtoWriter();
        uncompLib.writeBool(1, true);
        uncompLib.writeEnum(2, 2);
        opt.writeMessageAlways(2, uncompLib.toByteArray());

        // store_archive = { enabled: true }
        ProtoWriter storeArchive = new ProtoWriter();
        storeArchive.writeBool(1, true);
        opt.writeMessageAlways(6, storeArchive.toByteArray());

        config.writeMessageAlways(2, opt.toByteArray());

        // 3. Compression
        ProtoWriter comp = new ProtoWriter();
        for (String glob : DEFAULT_UNCOMPRESSED_GLOBS) {
            comp.writeString(1, glob);
        }
        config.writeMessageAlways(3, comp.toByteArray());

        return config.toByteArray();
    }

    public static byte[] buildNativePb(Set<String> nativeDirs) {
        ProtoWriter nat = new ProtoWriter();
        for (String dir : nativeDirs) {
            int abiAlias = mapAbiAlias(dir);
            if (abiAlias == 0) continue;

            ProtoWriter abiW = new ProtoWriter();
            abiW.writeEnum(1, abiAlias);

            ProtoWriter targetingW = new ProtoWriter();
            targetingW.writeMessageAlways(1, abiW.toByteArray());

            ProtoWriter tndW = new ProtoWriter();
            tndW.writeString(1, dir); // e.g. "lib/arm64-v8a"
            tndW.writeMessageAlways(2, targetingW.toByteArray());

            nat.writeMessageAlways(1, tndW.toByteArray());
        }
        return nat.toByteArray();
    }

    public static byte[] buildAssetsPb(Set<String> assetDirs) {
        ProtoWriter assets = new ProtoWriter();
        for (String dir : assetDirs) {
            ProtoWriter tadW = new ProtoWriter();
            tadW.writeString(1, dir); // e.g. "assets" or "assets/fonts"
            tadW.writeEmptyMessage(2); // empty AssetsDirectoryTargeting {}
            assets.writeMessageAlways(1, tadW.toByteArray());
        }
        return assets.toByteArray();
    }

    private static int mapAbiAlias(String libDir) {
        if (libDir == null) return 0;
        String lower = libDir.toLowerCase(Locale.US);
        if (lower.endsWith("/armeabi")) return 1;
        if (lower.endsWith("/armeabi-v7a")) return 2;
        if (lower.endsWith("/arm64-v8a")) return 3;
        if (lower.endsWith("/x86")) return 4;
        if (lower.endsWith("/x86_64")) return 5;
        if (lower.endsWith("/mips")) return 6;
        if (lower.endsWith("/mips64")) return 7;
        if (lower.endsWith("/riscv64")) return 8;
        return 0;
    }
}
