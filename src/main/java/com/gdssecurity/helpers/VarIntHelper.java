/**
 * Copyright 2023 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gdssecurity.helpers;

import org.apache.parquet.bytes.BytesUtils;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Helper class for Variable-Size Integer (VarInt) Parsing
 */
public class VarIntHelper {

    /**
     * Extract a variable-size integer from encoded bytes
     * @param data - a byte array containing the encoded bytes
     * @return - a JSONObject containing both the parsed VarInt value and the number of encoded bytes
     */
    public static JSONObject extractVarInt(byte[] data) throws IOException{
        JSONObject toReturn = new JSONObject();
        InputStream dataStream = new ByteArrayInputStream(data);
        int varIntValue = BytesUtils.readUnsignedVarInt(dataStream);
        dataStream.close();
        toReturn.put("result", varIntValue);
        ByteArrayOutputStream lengthStream = new ByteArrayOutputStream();
        BytesUtils.writeUnsignedVarInt(varIntValue, lengthStream);
        toReturn.put("bytesRead", lengthStream.size());
        lengthStream.close();
        return toReturn;
    }

    /**
     * Encode a value as a VarInt
     * @param toEncode - the value to be encoded as a VarInt
     * @return - a byte array containing the encoded VarInt
     */
    public static byte[] encodeVarInt(int toEncode) throws IOException {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        BytesUtils.writeUnsignedVarInt(toEncode, outStream);
        return outStream.toByteArray();
    }
}
