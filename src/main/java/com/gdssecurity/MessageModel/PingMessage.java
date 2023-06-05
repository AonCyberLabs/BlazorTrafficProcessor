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
import com.gdssecurity.helpers.VarIntHelper;
import org.json.JSONObject;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Based off the "PingMessage" specification: https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#ping-message-encoding-1
 * Class to implement handling of "Ping" messages
 */
public class PingMessage extends GenericMessage {

    /**
     * Constructs a PingMessage from raw BlazorPack bytes
     * @param raw - the raw BlazorPack bytes to parse
     * @param api - an instance of the Montoya API
     */
    public PingMessage(byte[] raw, MontoyaApi api) {
        super(raw, api);
    }

    /**
     * Constructs a PingMessage from a raw JSON object
     * @param msg - the raw JSON object to parse
     * @param api - an instance of the Montoya API
     */
    public PingMessage(JSONObject msg, MontoyaApi api) {
        super(msg, api);
    }

    /**
     * Checks if the provided JSON matches the structure of a Ping message
     * @param msg - the JSON object to validate
     * @return true if valid, false otherwise
     */
    public boolean validateJson(JSONObject msg) {
        if (!msg.has("MessageType")) {
            this.logging.logToError("[-] ERROR initializing BlazorPack from JSON. Input missing one of required keys: [MessageType].");
            return false;
        }
        if (!((msg.get("MessageType")) instanceof Integer)) {
            this.logging.logToError("[-] ERROR initializing BlazorPack from JSON. MessageType is required to be an integer.");
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
        JSONObject message = new JSONObject();
        message.put("MessageType", msgType);
        this.jsonMessage = message;
        unpacker.close();
    }
}

