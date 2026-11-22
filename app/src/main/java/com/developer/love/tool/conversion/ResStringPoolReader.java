package com.developer.love.tool.conversion;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Parses Android ResStringPool chunks (UTF-8 and UTF-16, including optional style spans).
 */
public class ResStringPoolReader {

    public static class Span {
        public final String tag;
        public final int firstChar;
        public final int lastChar;

        public Span(String tag, int firstChar, int lastChar) {
            this.tag = tag;
            this.firstChar = firstChar;
            this.lastChar = lastChar;
        }
    }

    private static final int UTF8_FLAG = 1 << 8;

    private final String[] strings;
    private final List<List<Span>> styles;

    private ResStringPoolReader(String[] strings, List<List<Span>> styles) {
        this.strings = strings;
        this.styles = styles;
    }

    public int size() {
        return strings.length;
    }

    public String getString(int index) {
        if (index < 0 || index >= strings.length) return null;
        return strings[index];
    }

    public List<Span> getSpans(int index) {
        if (index < 0 || index >= styles.size()) return Collections.emptyList();
        return styles.get(index);
    }

    public static ResStringPoolReader parse(byte[] data, int chunkStart) {
        if (chunkStart < 0 || chunkStart + 28 > data.length) {
            throw new IllegalArgumentException("Truncated ResStringPool header.");
        }
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int type = buf.getShort(chunkStart) & 0xFFFF;
        if (type != 0x0001) {
            throw new IllegalArgumentException("Expected RES_STRING_POOL_TYPE (0x0001), got 0x" + Integer.toHexString(type));
        }
        int headerSize = buf.getShort(chunkStart + 2) & 0xFFFF;
        int chunkSize = buf.getInt(chunkStart + 4);
        int chunkEnd = Math.min(chunkStart + Math.max(0, chunkSize), data.length);

        int stringCount = buf.getInt(chunkStart + 8);
        int styleCount = buf.getInt(chunkStart + 12);
        int flags = buf.getInt(chunkStart + 16);
        int stringsStart = buf.getInt(chunkStart + 20);
        int stylesStart = buf.getInt(chunkStart + 24);

        if (stringCount < 0 || stringCount > 10_000_000 || styleCount < 0 || styleCount > 10_000_000) {
            throw new IllegalArgumentException("Invalid ResStringPool counts.");
        }

        boolean isUtf8 = (flags & UTF8_FLAG) != 0;

        int offsetsBase = chunkStart + headerSize;
        int stringsDataBase = chunkStart + stringsStart;
        int stylesDataBase = chunkStart + stylesStart;

        String[] strings = new String[stringCount];
        for (int i = 0; i < stringCount; i++) {
            int offsetPos = offsetsBase + i * 4;
            if (offsetPos + 4 > chunkEnd) {
                strings[i] = "";
                continue;
            }
            int strOffset = buf.getInt(offsetPos);
            int pos = stringsDataBase + strOffset;
            if (strOffset < 0 || pos < 0 || pos >= chunkEnd) {
                strings[i] = "";
                continue;
            }
            if (isUtf8) {
                // Skip UTF-16 char length (1 or 2 bytes)
                int b0 = data[pos++] & 0xFF;
                if ((b0 & 0x80) != 0) {
                    if (pos >= chunkEnd) {
                        strings[i] = "";
                        continue;
                    }
                    pos++;
                }
                if (pos >= chunkEnd) {
                    strings[i] = "";
                    continue;
                }
                // Read UTF-8 byte length (1 or 2 bytes)
                int byteLen = data[pos++] & 0xFF;
                if ((byteLen & 0x80) != 0) {
                    if (pos >= chunkEnd) {
                        strings[i] = "";
                        continue;
                    }
                    int b2 = data[pos++] & 0xFF;
                    byteLen = ((byteLen & 0x7F) << 8) | b2;
                }
                if (byteLen < 0 || pos + byteLen > chunkEnd) {
                    strings[i] = "";
                } else {
                    strings[i] = decodeModifiedUtf8(data, pos, byteLen);
                }
            } else {
                // UTF-16LE
                if (pos + 2 > chunkEnd) {
                    strings[i] = "";
                    continue;
                }
                int charLen = buf.getShort(pos) & 0xFFFF;
                pos += 2;
                if ((charLen & 0x8000) != 0) {
                    if (pos + 2 > chunkEnd) {
                        strings[i] = "";
                        continue;
                    }
                    int low = buf.getShort(pos) & 0xFFFF;
                    pos += 2;
                    charLen = ((charLen & 0x7FFF) << 16) | low;
                }
                int byteLen = charLen * 2;
                if (byteLen < 0 || pos + byteLen > chunkEnd) {
                    strings[i] = "";
                } else {
                    strings[i] = new String(data, pos, byteLen, StandardCharsets.UTF_16LE);
                }
            }
        }

        List<List<Span>> styles = new ArrayList<>();
        if (styleCount > 0 && stylesStart > 0) {
            int styleOffsetsBase = offsetsBase + stringCount * 4;
            for (int i = 0; i < styleCount; i++) {
                int stOffsetPos = styleOffsetsBase + i * 4;
                if (stOffsetPos + 4 > chunkEnd) {
                    styles.add(Collections.emptyList());
                    continue;
                }
                int stOffset = buf.getInt(stOffsetPos);
                int pos = stylesDataBase + stOffset;
                List<Span> spanList = new ArrayList<>();
                if (stOffset >= 0 && pos >= 0) {
                    while (pos + 4 <= chunkEnd) {
                        int nameIdx = buf.getInt(pos);
                        if (nameIdx == 0xFFFFFFFF) {
                            break;
                        }
                        if (pos + 12 > chunkEnd) break;
                        int firstChar = buf.getInt(pos + 4);
                        int lastChar = buf.getInt(pos + 8);
                        pos += 12;
                        String tag = (nameIdx >= 0 && nameIdx < strings.length) ? strings[nameIdx] : "";
                        spanList.add(new Span(tag, firstChar, lastChar));
                    }
                }
                styles.add(spanList);
            }
        }

        return new ResStringPoolReader(strings, styles);
    }

    /**
     * Android ResStringPool UTF-8 pools encode supplementary Unicode characters (e.g. emojis U+10000+)
     * as 6-byte CESU-8 / Modified UTF-8 surrogate pairs (two 3-byte UTF-8 sequences for high and low
     * UTF-16 surrogates). StandardCharsets.UTF_8 replaces those with U+FFFD, whereas this decoder
     * preserves both CESU-8 surrogate pairs and standard 4-byte UTF-8 sequences cleanly.
     */
    static String decodeModifiedUtf8(byte[] data, int offset, int length) {
        if (length <= 0) return "";
        StringBuilder sb = new StringBuilder(length);
        int i = offset;
        int end = offset + length;
        while (i < end) {
            int b0 = data[i++] & 0xFF;
            if ((b0 & 0x80) == 0) {
                sb.append((char) b0);
            } else if ((b0 & 0xE0) == 0xC0) {
                if (i < end && (data[i] & 0xC0) == 0x80) {
                    int b1 = data[i++] & 0x3F;
                    sb.append((char) (((b0 & 0x1F) << 6) | b1));
                } else {
                    sb.append('\uFFFD');
                }
            } else if ((b0 & 0xF0) == 0xE0) {
                if (i + 1 < end && (data[i] & 0xC0) == 0x80 && (data[i + 1] & 0xC0) == 0x80) {
                    int b1 = data[i++] & 0x3F;
                    int b2 = data[i++] & 0x3F;
                    // Yields exact UTF-16 code unit, including high/low surrogates (CESU-8)
                    sb.append((char) (((b0 & 0x0F) << 12) | (b1 << 6) | b2));
                } else {
                    sb.append('\uFFFD');
                }
            } else if ((b0 & 0xF8) == 0xF0) {
                if (i + 2 < end
                        && (data[i] & 0xC0) == 0x80
                        && (data[i + 1] & 0xC0) == 0x80
                        && (data[i + 2] & 0xC0) == 0x80) {
                    int b1 = data[i++] & 0x3F;
                    int b2 = data[i++] & 0x3F;
                    int b3 = data[i++] & 0x3F;
                    int cp = ((b0 & 0x07) << 18) | (b1 << 12) | (b2 << 6) | b3;
                    if (cp <= 0x10FFFF && cp >= 0x10000) {
                        sb.appendCodePoint(cp);
                    } else {
                        sb.append('\uFFFD');
                    }
                } else {
                    sb.append('\uFFFD');
                }
            } else {
                sb.append('\uFFFD');
            }
        }
        return sb.toString();
    }
}
