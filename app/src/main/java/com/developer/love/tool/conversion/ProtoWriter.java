package com.developer.love.tool.conversion;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Zero-dependency Pure Java Protocol Buffers (proto3) wire-format encoder.
 */
public final class ProtoWriter {

    public static final int WIRE_VARINT = 0;
    public static final int WIRE_FIXED64 = 1;
    public static final int WIRE_LENGTH_DELIMITED = 2;
    public static final int WIRE_FIXED32 = 5;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    public void writeTag(int fieldNumber, int wireType) {
        writeRawVarint32((fieldNumber << 3) | wireType);
    }

    public void writeUInt32(int fieldNumber, int value) {
        if (value == 0) return;
        writeTag(fieldNumber, WIRE_VARINT);
        writeRawVarint32(value);
    }

    public void writeUInt32Always(int fieldNumber, int value) {
        writeTag(fieldNumber, WIRE_VARINT);
        writeRawVarint32(value);
    }

    public void writeInt32(int fieldNumber, int value) {
        if (value == 0) return;
        writeTag(fieldNumber, WIRE_VARINT);
        if (value >= 0) {
            writeRawVarint32(value);
        } else {
            // Protobuf spec: negative int32 is encoded as 10-byte two's complement 64-bit varint
            writeRawVarint64((long) value);
        }
    }

    public void writeInt32Always(int fieldNumber, int value) {
        writeTag(fieldNumber, WIRE_VARINT);
        if (value >= 0) {
            writeRawVarint32(value);
        } else {
            writeRawVarint64((long) value);
        }
    }

    public void writeEnum(int fieldNumber, int value) {
        writeInt32(fieldNumber, value);
    }

    public void writeBool(int fieldNumber, boolean value) {
        if (!value) return;
        writeTag(fieldNumber, WIRE_VARINT);
        out.write(1);
    }

    public void writeFloat(int fieldNumber, float value) {
        if (value == 0.0f && Float.floatToRawIntBits(value) == 0) return;
        writeTag(fieldNumber, WIRE_FIXED32);
        writeRawLittleEndian32(Float.floatToRawIntBits(value));
    }

    public void writeFloatAlways(int fieldNumber, float value) {
        writeTag(fieldNumber, WIRE_FIXED32);
        writeRawLittleEndian32(Float.floatToRawIntBits(value));
    }

    public void writeString(int fieldNumber, String value) {
        if (value == null || value.isEmpty()) return;
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeBytes(fieldNumber, bytes);
    }

    public void writeBytes(int fieldNumber, byte[] value) {
        if (value == null || value.length == 0) return;
        writeTag(fieldNumber, WIRE_LENGTH_DELIMITED);
        writeRawVarint32(value.length);
        out.write(value, 0, value.length);
    }

    public void writeMessage(int fieldNumber, byte[] serializedMessage) {
        if (serializedMessage == null || serializedMessage.length == 0) return;
        writeTag(fieldNumber, WIRE_LENGTH_DELIMITED);
        writeRawVarint32(serializedMessage.length);
        out.write(serializedMessage, 0, serializedMessage.length);
    }

    public void writeMessageAlways(int fieldNumber, byte[] serializedMessage) {
        int len = serializedMessage != null ? serializedMessage.length : 0;
        writeTag(fieldNumber, WIRE_LENGTH_DELIMITED);
        writeRawVarint32(len);
        if (len > 0) {
            out.write(serializedMessage, 0, len);
        }
    }

    public void writeEmptyMessage(int fieldNumber) {
        writeTag(fieldNumber, WIRE_LENGTH_DELIMITED);
        writeRawVarint32(0);
    }

    public void writeRawVarint32(int value) {
        long v = value & 0xFFFFFFFFL;
        while ((v & ~0x7FL) != 0) {
            out.write((int) ((v & 0x7F) | 0x80));
            v >>>= 7;
        }
        out.write((int) v);
    }

    public void writeRawVarint64(long value) {
        while ((value & ~0x7FL) != 0) {
            out.write((int) ((value & 0x7F) | 0x80));
            value >>>= 7;
        }
        out.write((int) value);
    }

    private void writeRawLittleEndian32(int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 24) & 0xFF);
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }

    public int size() {
        return out.size();
    }
}
