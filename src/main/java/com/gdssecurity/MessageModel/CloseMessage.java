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
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Based off the "CloseMessage" specification: https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#close-message-encoding-1
 * Class to implement handling of "Close" messages
 */
public class CloseMessage extends GenericMessage {

    /**
     * Constructor to build a CloseMessage from raw BlazorPack bytes
     * @param raw - the raw BlazorPack bytes to parse
     * @param api - an instance of the Montoya API
     */
    public CloseMessage(byte[] raw, MontoyaApi api) {
        super(raw, api);
    }

    /**
     * Constructor to build a CloseMessage from a raw JSON object
     * @param msg - the raw JSON object to parse
     * @param api - an instance of the Montoya API
     */
    public CloseMessage(JSONObject msg, MontoyaApi api) {
        super(msg, api);
    }

    /**
     * Checks to see if the provided JSON matches the structure of a Close message
     * @param msg - the JSON object to validate
     * @return true if valid, false otherwise
     */
    public boolean validateJson(JSONObject msg) {
        if (!msg.has("MessageType") | !msg.has("Error")) {
            this.logging.logToError("[-] Error validating CloseMessage JSON: missing one of required keys: [MessageType, Error].");
            return false;
        }
        if (!(msg.get("MessageType") instanceof Integer)) {
            this.logging.logToError("[-] Error validating CloseMessage JSON: input for 'MessageType' must be an integer.");
            return false;
        }
        if (!((msg.get("Error")) instanceof String)) {
            this.logging.logToError("[-] Error validating CloseMessage JSON: input for 'Error' must be a string.");
            return false;
        }
        if (msg.has("AllowReconnect")) {
            if (!(msg.get("AllowReconnect") instanceof Boolean)) {
                this.logging.logToError("[-] Error validating CloseMessage JSON: input for 'AllowReconnect' must be a boolean.");
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
        if (this.jsonMessage.has("AllowReconnect")) {
            packer.packArrayHeader(BTPConstants.CLOSE_RECONNECT_ARRAY_HEADER);
            packer.packInt(this.jsonMessage.getInt("MessageType"));
            if (this.jsonMessage.getString("Error").equalsIgnoreCase("null")) {
                packer.packNil();
            } else {
                packer.packString(this.jsonMessage.getString("Error"));
            }
            packer.packBoolean(this.jsonMessage.getBoolean("AllowReconnect"));
        } else {
            packer.packArrayHeader(BTPConstants.CLOSE_NORECON_ARRAY_HEADER);
            packer.packInt(this.jsonMessage.getInt("MessageType"));
            if (this.jsonMessage.getString("Error").equalsIgnoreCase("null")) {
                packer.packNil();
            } else {
                packer.packString(this.jsonMessage.getString("Error"));
            }
            packer.packString(this.jsonMessage.getString("Error"));
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
        String error = "null";
        if (!unpacker.tryUnpackNil()) {
            error = unpacker.unpackString();
        }
        Boolean allowReconnect = null;
        if (unpacker.hasNext()) {
            allowReconnect = unpacker.unpackBoolean();
        }
        JSONObject message = new JSONObject();
        message.put("MessageType", msgType);
        message.put("Error", error);
        if (allowReconnect != null) {
            message.put("AllowReconnect", allowReconnect);
        }
        this.jsonMessage = message;
        unpacker.close();
    }
}
