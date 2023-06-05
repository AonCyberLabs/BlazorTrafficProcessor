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
 * Based off the "StreamItem" specification: https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#streamitem-message-encoding-1
 * Class to implement handling of "StreamItem" messages
 */
public class StreamItemMessage extends GenericMessage {

    /**
     * Constructs a StreamItemMessage from raw BlazorPack bytes
     * @param raw - the raw BlazorPack bytes to parse
     * @param api - an instance of the Montoya API
     */
    public StreamItemMessage(byte[] raw, MontoyaApi api) {
        super(raw, api);
    }

    /**
     * Constructs a StreamItemMessage from a raw JSON object
     * @param msg - the raw JSON object to parse
     * @param api - an instance of the Montoya API
     */
    public StreamItemMessage(JSONObject msg, MontoyaApi api) {
        super(msg, api);
    }

    /**
     * Checks if the provided JSON matches the structure of a StreamItem message
     * @param msg - the JSON object to validate
     * @return true if valid, false otherwise
     */
    public boolean validateJson(JSONObject msg) {
        if (!msg.has("MessageType") | !msg.has("Headers") | !msg.has("Item")) {
            this.logging.logToError("[-] ERROR initializing BlazorPack from JSON. Input missing one of required keys: [MessageType, Headers, Item].");
            return false;
        }
        if (!((msg.get("MessageType")) instanceof Integer)) {
            this.logging.logToError("[-] ERROR initializing BlazorPack from JSON. MessageType is required to be an integer.");
            return false;
        }
        if (!(msg.get("Headers") instanceof Integer)) {
            this.logging.logToError("[-] Error validating InvocationMessage JSON: input for 'Headers' must be an integer.");
            return false;
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
        packer.packInt(this.jsonMessage.getInt("MessageType"));
        packer.packMapHeader(BTPConstants.DEFAULT_MAP_HEADER);
        if (!this.jsonMessage.has("InvocationId")) {
            packer.packNil();
        } else {
            packer.packString(this.jsonMessage.getString("InvocationId"));
        }
        String itemType = this.jsonMessage.get("Item").getClass().getSimpleName().toLowerCase();
        switch (itemType) {
            case "boolean":
                packer.packBoolean(this.jsonMessage.getBoolean("Item"));
                break;
            case "string":
                packer.packString(this.jsonMessage.getString("Item"));
                break;
            case "integer":
                packer.packInt(this.jsonMessage.getInt("Item"));
                break;
            default:
                packer.packValue((ImmutableValue) this.jsonMessage.get("Item"));
                break;
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
        if (mapHeader != BTPConstants.DEFAULT_MAP_HEADER) {
            this.logging.logToOutput("[*] DEBUG - initJsonFromMessage: unpacked map value != 0 for the 'Headers' attribute: " + mapHeader);
        }
        String invocationId = null;
        if (!unpacker.tryUnpackNil()) {
            invocationId = unpacker.unpackString();
        }
        Object item = null;
        MessageFormat nextTokenFormat = unpacker.getNextFormat();
        ValueType nextTokenType = nextTokenFormat.getValueType();
        switch (nextTokenType) {
            case BOOLEAN:
                item = unpacker.unpackBoolean();
                break;
            case STRING:
                item = unpacker.unpackString();
                break;
            case INTEGER:
                item = unpacker.unpackInt();
                break;
            default:
                item = unpacker.unpackValue();
                break;
        }
        JSONObject message = new JSONObject();
        message.put("MessageType", msgType);
        message.put("Headers", mapHeader);
        message.put("InvocationId", invocationId);
        message.put("Item", item);
        this.jsonMessage = message;
        unpacker.close();
    }
}
