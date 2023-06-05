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
package com.gdssecurity.MessageModel;

import burp.api.montoya.MontoyaApi;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.VarIntHelper;
import org.json.JSONArray;
import org.json.JSONObject;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessageFormat;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.ImmutableValue;
import org.msgpack.value.ValueType;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Class to store and process "Invocation" blazorpack messages
 * This is predominantly what is seen while proxying blazor traffic
 * Based on the "InvocationMessage" spec - https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#invocation-message-encoding-1
 * Format: [1, Headers, InvocationId, Target, [Arguments], [StreamIds]]
 * 1            => Integer representing the message type. "Invocation" messages are always 1, haven't seen any other message type proxied while testing a Blazor app
 * Headers      => Map containing headers. String keys and String values. While testing example app, this was always set to a null map (0x80)
 * InvocationId => Can either be a string or null. While testing example app, always null (0xc0).
 * Target       => The target function name (must be as expected by the callee's binder; a.k.a. "Method")
 * Arguments    => An array containing arguments for the function indicated in "Target". Size of array and types within will vary per "Target".
 * StreamIds    => This field was not seen during testing, currently just gets set to null
 */
public class InvocationMessage extends GenericMessage {

    /**
     * Creates a new InvocationMessage object, given a raw blazorpack body
     * @param raw - a byte array containing the raw blazorpack bytes
     * @param api - the Burp callback functions
     */
    public InvocationMessage(byte[] raw, MontoyaApi api) {
        super(raw, api);
    }

    /**
     * Creates a new InvocationMessage object, given a JSON blazorpack body
     * @param msg - a JSONObject containing all the message's info and parameters
     * @param api - the Burp callback functions
     */
    public InvocationMessage(JSONObject msg, MontoyaApi api) {
        super(msg, api);
    }

    /**
     * Validates that a given JSON object matches the expected blazorpack format
     * Spec: https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#messagepack-msgpack-encoding
     * @param msg - a JSONObject representation of the message to validate
     * @return true if the JSON is valid, false otherwise
     */
    public boolean validateJson(JSONObject msg) {
        // Required keys
        if (!msg.has("MessageType") || !msg.has("Headers") || !msg.has("Target") || !msg.has("Arguments")) {
            this.logging.logToError("[-] Error validating InvocationMessage JSON: input is missing one of the required keys: [MessageType, Headers, Target, Arguments]");
            return false;
        }
        // Validate Message Type
        if (!(msg.get("MessageType") instanceof Integer)) {
            this.logging.logToError("[-] Error validating InvocationMessage JSON: input for 'MessageType' must be an integer.");
            return false;
        }
        // Validate Invocation ID is either null or string, if it exists
        if (msg.has("InvocationId")) {
            if (!(msg.get("InvocationId") instanceof String)) {
                this.logging.logToError("[-] Error validating InvocationMessage JSON: input for 'InvocationId' must be a String.");
                return false;
            }
        }
        // Validate Headers (for now just make sure it's an empty map/int = 0)
        if (!(msg.get("Headers") instanceof Integer)) {
            this.logging.logToError("[-] Error validating InvocationMessage JSON: input for 'Headers' must be an integer.");
            return false;
        }
        // Validate Target is a String
        if (!(msg.get("Target") instanceof String)) {
            this.logging.logToError("[-] Error validating InvocationMessage JSON: input for 'Target' must be a String.");
            return false;
        }
        // Validate Arguments is a JSON array
        if (!(msg.get("Arguments") instanceof JSONArray)) {
            this.logging.logToError("[-] Error validating InvocationMessage JSON: input for 'Arguments' must be a JSONArray.");
            return false;
        }
        // Validate StreamIds, if it exists
        if (msg.has("StreamIds")) {
            if (!(msg.get("StreamIds") instanceof JSONArray)) {
                this.logging.logToError("[-] Error validating InvocationMessage JSON: input for 'StreamIds' must be a JSONArray.");
                return false;
            }
        }
        return true;
    }

    /**
     * Packs a message from JSON to BlazorPack, end result is the "blazorMessage" class variable being populated with the packed data
     * @throws IOException - this exception is thrown by all "pack" actions (i.e. "packArrayHeader", "packInt", etc.). Catch and handle this exception in the caller.
     */
    public void initBlazorFromJson() throws IOException {
        MessageBufferPacker buffPacker = MessagePack.newDefaultBufferPacker();
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        buffPacker.packArrayHeader(BTPConstants.INVOCATION_ARRAY_HEADER); // Pack the default array header for InvocationMessages
        buffPacker.packInt(this.jsonMessage.getInt("MessageType"));
        buffPacker.packMapHeader(BTPConstants.DEFAULT_MAP_HEADER);
        if (!this.jsonMessage.has("InvocationId")) {
            buffPacker.packNil();
        } else {
            buffPacker.packString(this.jsonMessage.getString("InvocationId"));
        }
        buffPacker.packString(this.jsonMessage.getString("Target"));
        int argsLength = this.jsonMessage.getJSONArray("Arguments").length();
        buffPacker.packArrayHeader(argsLength);
        JSONArray arguments = this.jsonMessage.getJSONArray("Arguments");
        for (int i = 0; i < argsLength; i++) {
            String argType = arguments.get(i).getClass().getSimpleName().toLowerCase();
            switch (argType) {
                case "boolean":
                    buffPacker.packBoolean(arguments.getBoolean(i));
                    break;
                case "string":
                    if (arguments.getString(i).equalsIgnoreCase("null")) {
                        buffPacker.packNil();
                        break;
                    }
                    buffPacker.packString(arguments.getString(i));
                    break;
                case "float":
                    buffPacker.packFloat(arguments.getFloat(i));
                    break;
                case "integer":
                    buffPacker.packInt(arguments.getInt(i));
                    break;
                case "jsonarray":
                    buffPacker.packString(arguments.getJSONArray(i).toString());
                    break;
                case "jsonobject":
                    JSONObject binaryObj = arguments.getJSONObject(i);
                    int binaryHeader = binaryObj.getInt("BinaryHeader");
                    buffPacker.packBinaryHeader(binaryHeader);
                    byte[] binaryBytes = DatatypeConverter.parseHexBinary(binaryObj.getString("BinaryBytes"));
                    buffPacker.writePayload(binaryBytes);
                    break;
                default:
                    buffPacker.packValue((ImmutableValue) arguments.get(i));
                    break;
            }
        }
        int streamIdSize = 0;
        if (this.jsonMessage.has("StreamIds")) {
            streamIdSize = this.jsonMessage.getJSONArray("StreamIds").toString().length();
            buffPacker.packRawStringHeader(streamIdSize);
        }
        byte[] sizeBytes = VarIntHelper.encodeVarInt((int) buffPacker.getTotalWrittenBytes() + streamIdSize);
        byte[] packedBytes = buffPacker.toByteArray();
        message.write(sizeBytes); // Write the VarInt size bytes
        message.write(packedBytes); // Write the packed data
        if (streamIdSize != 0) {
            message.write(this.jsonMessage.getJSONArray("StreamIds").toString().getBytes(StandardCharsets.UTF_8)); // Write raw JSON string if present
        }
        this.blazorMessage = message;
    }

    /**
     * Unpacks a message from BlazorPack to JSON, end result is the "jsonMessage" class variable being populated with the unpacked data
     * @throws IOException - this exception is thrown by all "unpack" actions. Catch and handle this exception in the caller.
     */
    public void initJsonFromMessage() throws IOException {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(this.raw);
        int arrayHeader = unpacker.unpackArrayHeader();
        int msgType = unpacker.unpackInt();
        int mapHeader = unpacker.unpackMapHeader();
        if (mapHeader != BTPConstants.DEFAULT_MAP_HEADER) {
            this.logging.logToOutput("[*] initJsonFromMessage: unpacked map value != 0 for the `Headers` attribute.");
        }
        String invocationId = null;
        if (!unpacker.tryUnpackNil()) { // Next token is "invocationId", can be null or string. Unpack if string
            invocationId = unpacker.unpackString();
            this.logging.logToOutput("[*] initJsonFromMessage: unpacked invocationId = " + invocationId);
        }
        String method = unpacker.unpackString();
        int argsLength = unpacker.unpackArrayHeader();
        JSONArray args = new JSONArray();
        JSONArray streamIds = null;
        String rawStreamIds = null;
        for (int i = 0; i < argsLength; i++) {
            MessageFormat nextTokenFormat = unpacker.getNextFormat();
            ValueType nextTokenType = nextTokenFormat.getValueType();
            switch (nextTokenType) {
                case NIL:
                    unpacker.unpackNil();
                    args.put("null");
                    break;
                case BOOLEAN:
                    args.put(unpacker.unpackBoolean());
                    break;
                case STRING:
                    String argString = unpacker.unpackString().replace("\0", "");
                    if (argString.startsWith("[")) {
                        args.put(new JSONArray(argString + "]"));
                        break;
                    }
                    args.put(argString);
                    break;
                case FLOAT:
                    args.put(unpacker.unpackFloat());
                    break;
                case INTEGER:
                    args.put(unpacker.unpackInt());
                    break;
                case BINARY:
                    int binHeader = unpacker.unpackBinaryHeader();
                    byte[] bytes = unpacker.readPayload(binHeader);
                    StringBuilder hex = new StringBuilder();
                    for (byte b : bytes) {
                        hex.append(String.format(BTPConstants.HEX_FORMAT, b));
                    }
                    args.put(new JSONObject("{\"BinaryHeader\":" + binHeader + ",\"BinaryBytes\":\"" + hex + "\"}"));
                    break;
                default:
                    this.logging.logToOutput("[*] initJsonFromMessage: parsing arguments, unhandled type = " + nextTokenType);
                    break;
            }
        }
        JSONObject message = new JSONObject();
        message.put("MessageType", msgType);
        message.put("Headers", mapHeader);
        message.put("InvocationId", invocationId);
        message.put("Target", method);
        message.put("Arguments", args);
        message.put("StreamIds", streamIds);
        this.jsonMessage = message;
        unpacker.close();
    }
}
