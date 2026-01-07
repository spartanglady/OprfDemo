package com.oprf.util;

import com.oprf.CipherSuite;
import com.oprf.core.GroupElement;
import com.oprf.exception.OprfException;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Serialization utilities for OPRF protocol elements.
 */
public final class Serialization {

    private Serialization() {
        // Utility class
    }

    /**
     * Serializes a list of group elements to bytes.
     * Format: count || element1 || element2 || ...
     *
     * @param elements the elements to serialize
     * @return serialized bytes
     */
    public static byte[] serializeElements(List<GroupElement> elements) {
        if (elements.size() > 0xFFFF) {
            throw new IllegalArgumentException("Element count exceeds 65535");
        }
        ByteBuffer buffer = ByteBuffer.allocate(2 + elements.size() * CipherSuite.ELEMENT_LENGTH);
        buffer.putShort((short) elements.size());
        for (GroupElement element : elements) {
            buffer.put(element.toBytes());
        }
        return buffer.array();
    }

    /**
     * Deserializes a list of group elements from bytes.
     *
     * @param bytes the serialized data
     * @return list of group elements
     */
    public static List<GroupElement> deserializeElements(byte[] bytes) {
        if (bytes.length < 2) {
            throw OprfException.serializationError("Insufficient data for element list");
        }
        int count = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
        int expectedLength = 2 + count * CipherSuite.ELEMENT_LENGTH;
        if (bytes.length != expectedLength) {
            throw OprfException.serializationError("Expected " + expectedLength +
                    " bytes, got " + bytes.length);
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.getShort(); // consume count
        List<GroupElement> elements = new ArrayList<>(count);

        for (int i = 0; i < count; i++) {
            byte[] elementBytes = new byte[CipherSuite.ELEMENT_LENGTH];
            buffer.get(elementBytes);
            elements.add(GroupElement.fromBytes(elementBytes));
        }

        return elements;
    }

    /**
     * Converts an integer to a 2-byte big-endian representation (I2OSP).
     */
    public static byte[] i2osp2(int value) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException("Value out of range for 2-byte encoding");
        }
        return new byte[]{(byte) (value >> 8), (byte) value};
    }

    /**
     * Converts a 2-byte big-endian representation to an integer (OS2IP).
     */
    public static int os2ip2(byte[] bytes) {
        if (bytes.length != 2) {
            throw new IllegalArgumentException("Expected 2 bytes, got " + bytes.length);
        }
        return ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
    }
}
