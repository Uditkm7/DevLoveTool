package com.developer.love.tool.conversion;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;

/**
 * Converts Android Binary XML (ResXMLTree) from APKs into aapt.pb.XmlNode Protocol Buffer format
 * required inside Android App Bundles (base/manifest/AndroidManifest.xml and base/res/**\/*.xml).
 */
public final class BinaryXmlToProtoConverter {

    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int RES_XML_TYPE = 0x0003;
    private static final int RES_XML_START_NAMESPACE_TYPE = 0x0100;
    private static final int RES_XML_END_NAMESPACE_TYPE = 0x0101;
    private static final int RES_XML_START_ELEMENT_TYPE = 0x0102;
    private static final int RES_XML_END_ELEMENT_TYPE = 0x0103;
    private static final int RES_XML_CDATA_TYPE = 0x0104;
    private static final int RES_XML_RESOURCE_MAP_TYPE = 0x0180;

    private static class NsDecl {
        final String prefix;
        final String uri;
        final int lineNumber;

        NsDecl(String prefix, String uri, int lineNumber) {
            this.prefix = prefix;
            this.uri = uri;
            this.lineNumber = lineNumber;
        }
    }

    private static class XmlAttrData {
        String namespaceUri;
        String name;
        String value;
        int lineNumber;
        int resourceId;
        byte[] compiledItem;
    }

    private static class ChildItem {
        final boolean isText;
        final XmlElemData element;
        final String text;
        final int lineNumber;

        ChildItem(XmlElemData element, int lineNumber) {
            this.isText = false;
            this.element = element;
            this.text = null;
            this.lineNumber = lineNumber;
        }

        ChildItem(String text, int lineNumber) {
            this.isText = true;
            this.element = null;
            this.text = text;
            this.lineNumber = lineNumber;
        }
    }

    private static class XmlElemData {
        final List<NsDecl> namespaces = new ArrayList<>();
        String namespaceUri;
        String name;
        int lineNumber;
        final List<XmlAttrData> attributes = new ArrayList<>();
        final List<ChildItem> children = new ArrayList<>();
    }

    private BinaryXmlToProtoConverter() {}

    public static boolean isBinaryXml(byte[] data) {
        if (data == null || data.length < 8) return false;
        int type = (data[0] & 0xFF) | ((data[1] & 0xFF) << 8);
        int headerSize = (data[2] & 0xFF) | ((data[3] & 0xFF) << 8);
        return type == RES_XML_TYPE && headerSize == 8;
    }

    public static byte[] convert(byte[] binaryXml, int appPackageId, Map<Integer, String> resIdToName) {
        if (!isBinaryXml(binaryXml)) {
            throw new IllegalArgumentException("Input is not a valid Android Binary XML (ResXMLTree).");
        }

        ByteBuffer buf = ByteBuffer.wrap(binaryXml).order(ByteOrder.LITTLE_ENDIAN);
        int totalSize = Math.min(buf.getInt(4), binaryXml.length);
        int pos = 8;

        ResStringPoolReader stringPool = null;
        int[] resourceMap = new int[0];

        List<NsDecl> pendingNamespaces = new ArrayList<>();
        Deque<XmlElemData> elementStack = new ArrayDeque<>();
        XmlElemData rootElement = null;

        while (pos + 8 <= totalSize) {
            int chunkType = buf.getShort(pos) & 0xFFFF;
            int headerSize = buf.getShort(pos + 2) & 0xFFFF;
            int chunkSize = buf.getInt(pos + 4);
            if (headerSize < 8 || headerSize > chunkSize || chunkSize <= 0 || pos + chunkSize > totalSize) {
                break;
            }

            if (chunkType == RES_STRING_POOL_TYPE) {
                stringPool = ResStringPoolReader.parse(binaryXml, pos);
            } else if (chunkType == RES_XML_RESOURCE_MAP_TYPE) {
                int count = (chunkSize - headerSize) / 4;
                resourceMap = new int[count];
                for (int i = 0; i < count; i++) {
                    resourceMap[i] = buf.getInt(pos + headerSize + i * 4);
                }
            } else if (chunkType == RES_XML_START_NAMESPACE_TYPE) {
                if (pos + headerSize + 8 > pos + chunkSize) {
                    pos += chunkSize;
                    continue;
                }
                int lineNumber = buf.getInt(pos + 8);
                int prefixIdx = buf.getInt(pos + headerSize);
                int uriIdx = buf.getInt(pos + headerSize + 4);
                String prefix = stringPool != null ? nullToEmpty(stringPool.getString(prefixIdx)) : "";
                String uri = stringPool != null ? nullToEmpty(stringPool.getString(uriIdx)) : "";
                pendingNamespaces.add(new NsDecl(prefix, uri, lineNumber));
            } else if (chunkType == RES_XML_START_ELEMENT_TYPE) {
                int ext = pos + headerSize;
                if (ext + 14 > pos + chunkSize) {
                    pos += chunkSize;
                    continue;
                }
                int lineNumber = buf.getInt(pos + 8);
                int nsIdx = buf.getInt(ext);
                int nameIdx = buf.getInt(ext + 4);
                int attrStart = buf.getShort(ext + 8) & 0xFFFF;
                int attrSize = buf.getShort(ext + 10) & 0xFFFF;
                int attrCount = buf.getShort(ext + 12) & 0xFFFF;

                XmlElemData elem = new XmlElemData();
                elem.lineNumber = lineNumber;
                elem.namespaceUri = nsIdx >= 0 && stringPool != null ? nullToEmpty(stringPool.getString(nsIdx)) : "";
                elem.name = nameIdx >= 0 && stringPool != null ? nullToEmpty(stringPool.getString(nameIdx)) : "";
                if (!pendingNamespaces.isEmpty()) {
                    elem.namespaces.addAll(pendingNamespaces);
                    pendingNamespaces.clear();
                }

                int attrBase = ext + attrStart;
                if (attrSize >= 20) {
                    for (int i = 0; i < attrCount; i++) {
                        int aPos = attrBase + i * attrSize;
                        if (aPos < ext || aPos + 20 > pos + chunkSize) break;

                        int aNsIdx = buf.getInt(aPos);
                        int aNameIdx = buf.getInt(aPos + 4);
                        int aRawValueIdx = buf.getInt(aPos + 8);
                        int dataType = buf.get(aPos + 15) & 0xFF;
                        int data = buf.getInt(aPos + 16);

                        XmlAttrData attr = new XmlAttrData();
                        attr.lineNumber = lineNumber;
                        attr.namespaceUri = aNsIdx >= 0 && stringPool != null ? nullToEmpty(stringPool.getString(aNsIdx)) : "";
                        attr.name = aNameIdx >= 0 && stringPool != null ? nullToEmpty(stringPool.getString(aNameIdx)) : "";
                        if (aNameIdx >= 0 && aNameIdx < resourceMap.length) {
                            attr.resourceId = resourceMap[aNameIdx];
                        }

                        String rawStr = (aRawValueIdx >= 0 && stringPool != null) ? stringPool.getString(aRawValueIdx) : null;
                        if (dataType == ResItemProtoEncoder.TYPE_STRING) {
                            String strVal = stringPool != null ? stringPool.getString(data) : rawStr;
                            attr.value = strVal != null ? strVal : "";
                            // For plain string attributes, compiled_item is omitted just like aapt2
                        } else {
                            attr.value = ResItemProtoEncoder.formatAttributeDisplayValue(
                                    dataType, data, rawStr, stringPool, appPackageId, resIdToName
                            );
                            attr.compiledItem = ResItemProtoEncoder.encodeItem(
                                    dataType, data, null, stringPool, appPackageId, resIdToName, null, null
                            );
                        }
                        elem.attributes.add(attr);
                    }
                }

                if (!elementStack.isEmpty()) {
                    elementStack.peek().children.add(new ChildItem(elem, lineNumber));
                } else {
                    rootElement = elem;
                }
                elementStack.push(elem);
            } else if (chunkType == RES_XML_END_ELEMENT_TYPE) {
                if (!elementStack.isEmpty()) {
                    elementStack.pop();
                }
            } else if (chunkType == RES_XML_CDATA_TYPE) {
                if (pos + headerSize + 4 <= pos + chunkSize) {
                    int lineNumber = buf.getInt(pos + 8);
                    int dataIdx = buf.getInt(pos + headerSize);
                    String text = dataIdx >= 0 && stringPool != null ? stringPool.getString(dataIdx) : "";
                    if (!elementStack.isEmpty() && text != null) {
                        elementStack.peek().children.add(new ChildItem(text, lineNumber));
                    }
                }
            } else if (chunkType == RES_XML_END_NAMESPACE_TYPE) {
                // Handled structurally via element stack
            }

            pos += chunkSize;
        }

        if (rootElement == null) {
            throw new IllegalStateException("No root XML element found in binary XML.");
        }

        return encodeXmlNodeElement(rootElement, rootElement.lineNumber);
    }

    private static byte[] encodeXmlNodeElement(XmlElemData elem, int lineNumber) {
        ProtoWriter node = new ProtoWriter();
        node.writeMessageAlways(1, encodeXmlElement(elem));
        if (lineNumber > 0) {
            node.writeMessage(3, encodeSourcePosition(lineNumber));
        }
        return node.toByteArray();
    }

    private static byte[] encodeXmlElement(XmlElemData elem) {
        ProtoWriter w = new ProtoWriter();
        for (NsDecl ns : elem.namespaces) {
            ProtoWriter nsW = new ProtoWriter();
            nsW.writeString(1, ns.prefix);
            nsW.writeString(2, ns.uri);
            if (ns.lineNumber > 0) {
                nsW.writeMessage(3, encodeSourcePosition(ns.lineNumber));
            }
            w.writeMessageAlways(1, nsW.toByteArray());
        }
        w.writeString(2, elem.namespaceUri);
        w.writeString(3, elem.name);

        for (XmlAttrData attr : elem.attributes) {
            ProtoWriter aW = new ProtoWriter();
            aW.writeString(1, attr.namespaceUri);
            aW.writeString(2, attr.name);
            aW.writeString(3, attr.value);
            if (attr.lineNumber > 0) {
                aW.writeMessage(4, encodeSourcePosition(attr.lineNumber));
            }
            aW.writeUInt32(5, attr.resourceId);
            if (attr.compiledItem != null && attr.compiledItem.length > 0) {
                aW.writeMessage(6, attr.compiledItem);
            }
            w.writeMessageAlways(4, aW.toByteArray());
        }

        for (ChildItem child : elem.children) {
            if (child.isText) {
                ProtoWriter txtNode = new ProtoWriter();
                txtNode.writeString(2, child.text);
                if (child.lineNumber > 0) {
                    txtNode.writeMessage(3, encodeSourcePosition(child.lineNumber));
                }
                w.writeMessageAlways(5, txtNode.toByteArray());
            } else {
                w.writeMessageAlways(5, encodeXmlNodeElement(child.element, child.lineNumber));
            }
        }
        return w.toByteArray();
    }

    private static byte[] encodeSourcePosition(int lineNumber) {
        ProtoWriter sp = new ProtoWriter();
        sp.writeUInt32(1, lineNumber);
        return sp.toByteArray();
    }

    private static String nullToEmpty(String s) {
        return s != null ? s : "";
    }
}
