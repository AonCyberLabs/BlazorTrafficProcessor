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
import burp.api.montoya.logging.Logging;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Abstract class to represent a generic BlazorPack message, specific message-types extend this class (i.e. Invocation, Stream, Close, etc.)
 * Overview of different message types: https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#overview
 */
public abstract class GenericMessage {

    public MontoyaApi _montoya;
    public Logging logging;
    public byte[] raw;
    public ByteArrayOutputStream blazorMessage;
    public JSONObject jsonMessage;

    /**
     * Construct a generic message object given the raw BlazorPack bytes
     * @param raw - a byte array containing the BlazorPack bytes
     * @param api - an instance of the Montoya API
     */
    public GenericMessage(byte[] raw, MontoyaApi api) {
        this.raw = raw;
        this._montoya = api;
        this.logging = this._montoya.logging();
        try {
            this.initJsonFromMessage();
        } catch (IOException e) {
            this.logging.logToError("[-] An error occurred creating the Message object: " + e.getMessage());
        }
    }

    /**
     * Construct a generic message object given a JSON representation of the message
     * @param msg - the JSON object containing the BlazorPack message
     * @param api - an instance of the Montoya API
     */
    public GenericMessage(JSONObject msg, MontoyaApi api) {
        this.jsonMessage = msg;
        this._montoya = api;
        this.logging = this._montoya.logging();
        if (validateJson(msg)) {
            try {
                this.initBlazorFromJson();
            } catch (IOException e) {
                this.logging.logToError("[-] GenericMessage - Error packing JSON into BlazorPack: " + e.getMessage());
            } catch (Exception e) {
                this.logging.logToError("[-] GenericMessage - Unexpected error while packing JSON into BlazorPack: " + e.getMessage());
            }
        } else {
            this.logging.logToError("[-] GenericMessage - Invalid JSON for message initialization.");
            this.jsonMessage = null;
        }
    }

    /**
     * Abstract function to validate a JSON object containing a BlazorPack message
     * Different types of messages will have different requirements, thus implementation is left up to each unique message type
     * @param msg - the JSON object containing the BlazorPack message to validate
     * @return true if valid, false otherwise
     */
    abstract boolean validateJson(JSONObject msg);

    /**
     * Initialize the blazorMessage class variable (containing raw BlazorPack bytes) based on a MessageType specification
     * @throws IOException - if there is an error writing to the output stream
     */
    abstract void initBlazorFromJson() throws IOException;

    /**
     * Initialize the jsonMessage class variable (containing BlazorPack JSON object) based on a MessageType specification
     * @throws IOException - if there is an error writing to the output stream
     */
    abstract void initJsonFromMessage() throws IOException;

    /**
     * Gets a JSON representation of the BlazorPack message as a string
     * @return - a stringified version of the JSON message
     */
    public String toJsonString() {
        return this.jsonMessage.toString(3);
    }

    /**
     * Gets the raw bytes of a BlazorPack message
     * @return - a byte array containing the raw BlazorPack bytes
     */
    public byte[] toBlazorBytes() {
        if(this.blazorMessage != null)
            return this.blazorMessage.toByteArray();
        else
            return new byte[]{};
    }

}
