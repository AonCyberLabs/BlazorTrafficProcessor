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
import org.json.JSONObject;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessageFormat;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.ImmutableValue;
import org.msgpack.value.ValueType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Based off the "CompletionMessage" specification: https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#completion-message-encoding-1
 * Class to implement handling of "Completion" messages
 */
public class CompletionMessage extends GenericMessage {

    /**
     * Constructor to build a CompletionMessage from raw BlazorPack bytes
     * @param raw - the raw BlazorPack bytes to parse
     * @param api - an instance of the Montoya API
     */
    public CompletionMessage(byte[] raw, MontoyaApi api) {
        super(raw, api);
    }

    /**
     * Constructor to build a CompletionMessage from a raw JSON object
     * @param msg - the raw JSON object to parse
     * @param api - an instance of the Montoya API
     */
    public CompletionMessage(JSONObject msg, MontoyaApi api) {
        super(msg, api);
    }

    /**
     * Checks to see if the provided JSON matches the structure of a Completion message
     * @param msg - the JSON object to validate
     * @return true if valid, false otherwise
     */
    public boolean validateJson(JSONObject msg) {
        if (!msg.has("MessageType") || !msg.has("Headers") || !msg.has("ResultKind")) {
            this.logging.logToError("[-] Error validating CompletionMessage JSON: input is missing one of required keys: [MessageType, Headers, ResultKind].");
            return false;
        }
        if (!(msg.get("MessageType") instanceof Integer)) {
            this.logging.logToError("[-] Error validating CompletionMessage JSON: MessageType is required to be an integer.");
            return false;
        }
        if (!(msg.get("Headers") instanceof Integer)) {
            this.logging.logToError("[-] Error validating CompletionMessage JSON: MessageType is required to be an integer.");
            return false;
        }
        if (msg.has("InvocationId")) {
            if (!(msg.get("InvocationId") instanceof String)) {
                this.logging.logToError("[-] Error validating CompletionMessage JSON: InvocationId is required to be a string.");
                return false;
            }
        }
        if (!(msg.get("ResultKind") instanceof Integer)) {
            this.logging.logToError("[-] Error validating CompletionMessage JSON: ResultKind is required to be an integer.");
            return false;
        }
        if (msg.getInt("ResultKind") < BTPConstants.RESULT_KIND_ERROR & msg.getInt("ResultKind") > BTPConstants.RESULT_KIND_NONVOID) {
            this.logging.logToError("[-] Error validating CompletionMessage JSON: ResultKind is required to be an integer between 1-3.");
            return false;
        }
        if (msg.getInt("ResultKind") == BTPConstants.RESULT_KIND_ERROR | msg.getInt("ResultKind") == BTPConstants.RESULT_KIND_NONVOID) {
            if (!msg.has("Result")) {
                this.logging.logToError("[-] Error validating CompletionMessage JSON: Result must be present if the ResultKind is 1 or 3.");
                return false;
            }
        }
        return true;
    }

    /**
     * Initializes the BlazorPack bytes from JSON
     * @throws IOException - if there are issues writing to the output stream
     */
    public void initBlazorFromJson() throws IOException {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        if (this.jsonMessage.has("ResultKind") && this.jsonMessage.getInt("ResultKind") == BTPConstants.RESULT_KIND_VOID) {
            packer.packArrayHeader(BTPConstants.COMPLETION_NORES_HEADER);
        } else {
            packer.packArrayHeader(BTPConstants.COMPLETION_RESULT_HEADER);
        }
        packer.packInt(this.jsonMessage.getInt("MessageType"));
        packer.packMapHeader(BTPConstants.DEFAULT_MAP_HEADER);
        if (!this.jsonMessage.has("InvocationId")) {
            packer.packNil();
        } else {
            packer.packString(this.jsonMessage.getString("InvocationId"));
        }
        packer.packInt(this.jsonMessage.getInt("ResultKind"));
        if (this.jsonMessage.has("Result")) {
            String resultType = jsonMessage.get("Result").getClass().getSimpleName().toLowerCase();
            switch (resultType) {
                case "boolean":
                    packer.packBoolean(jsonMessage.getBoolean("Result"));
                    break;
                case "string":
                    if (jsonMessage.getString("Result").equalsIgnoreCase("null")) {
                        packer.packNil();
                        break;
                    }
                    packer.packString(jsonMessage.getString("Result"));
                    break;
                case "integer":
                    packer.packInt(jsonMessage.getInt("Result"));
                    break;
                default:
                    packer.packValue((ImmutableValue) jsonMessage.get("Result"));
                    break;
            }
        }
        byte[] sizeBytes = VarIntHelper.encodeVarInt((int) packer.getTotalWrittenBytes());
        message.write(sizeBytes);
        message.write(packer.toByteArray());
        this.blazorMessage = message;
        packer.close();
    }

    /**
     * Initializes the JSON object from raw BlazorPack bytes
     * @throws IOException - if there are issues writing to the output stream
     */
    public void initJsonFromMessage() throws IOException {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(this.raw);
        int arrayHeader = unpacker.unpackArrayHeader();
        int msgType = unpacker.unpackInt();
        int mapHeader = unpacker.unpackMapHeader();
        if (mapHeader != 0) {
            this.logging.logToOutput("[*] initJsonFromMessage: unpacked map value != 0 for the 'Headers' attribute: " + mapHeader);
        }
        String invocationId = null;
        if (!unpacker.tryUnpackNil()) {
            invocationId = unpacker.unpackString();
        }
        /**
         * https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#completion-message-encoding-1
         * 1 = Error result, error message in Result string
         * 2 = Void result, no Result param
         * 3 = Non-void result, value in Result string
         */
        int resultKind = unpacker.unpackInt();
        Object result = null;
        if (resultKind == BTPConstants.RESULT_KIND_ERROR | resultKind == BTPConstants.RESULT_KIND_NONVOID) {
            MessageFormat nextTokenFormat = unpacker.getNextFormat();
            ValueType nextTokenType = nextTokenFormat.getValueType();
            switch (nextTokenType) {
                case BOOLEAN:
                    result = unpacker.unpackBoolean();
                    break;
                case STRING:
                    result = unpacker.unpackString();
                    break;
                case INTEGER:
                    result = unpacker.unpackInt();
                    break;
                default:
                    result = unpacker.unpackValue();
                    break;
            }
        }
        JSONObject message = new JSONObject();
        message.put("MessageType", msgType);
        message.put("Headers", mapHeader);
        message.put("InvocationId", invocationId);
        message.put("ResultKind", resultKind);
        message.put("Result", result);
        this.jsonMessage = message;
        unpacker.close();
    }
}
