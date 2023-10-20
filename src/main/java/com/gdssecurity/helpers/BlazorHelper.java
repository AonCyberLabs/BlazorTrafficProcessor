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

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.gdssecurity.MessageModel.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.regex.Matcher;

/**
 * Class that handles BlazorPacking and BlazorUnpacking (Serializing & De-serializing)
 * Includes helper functions to parse Blazor messages from byte arrays and instantiate Message objects
 */
public class BlazorHelper {

    private MontoyaApi _montoya;
    private Logging logging;

    /**
     * Creates a new instance of the BlazorHelper class
     * @param api - the Burp callback functions object
     */
    public BlazorHelper(MontoyaApi api) {
        this._montoya = api;
        this.logging = this._montoya.logging();
    }

    /**
     * Perform Blazor Serialization, from JSON to Blazor Bytes
     * @param blazorMessages - a JSONArray containing the blazor unpacked messages
     * @return - a byte array containing the serialized blazor bytes
     */
    public byte[] blazorPack(JSONArray blazorMessages) {
        ByteArrayOutputStream newBody = new ByteArrayOutputStream();
        try {
            for (int i = 0; i < blazorMessages.length(); i++) {
                int msgType = blazorMessages.getJSONObject(i).getInt("MessageType");
                GenericMessage message;
                switch (msgType) {
                    case BTPConstants.STREAMITEM:
                        message = new StreamItemMessage(blazorMessages.getJSONObject(i), this._montoya);
                        break;
                    case BTPConstants.COMPLETION:
                        message = new CompletionMessage(blazorMessages.getJSONObject(i), this._montoya);
                        break;
                    case BTPConstants.CANCELINVOCATION:
                        message = new CancelInvocationMessage(blazorMessages.getJSONObject(i), this._montoya);
                        break;
                    case BTPConstants.PING:
                        message = new PingMessage(blazorMessages.getJSONObject(i), this._montoya);
                        break;
                    case BTPConstants.CLOSE:
                        message = new CloseMessage(blazorMessages.getJSONObject(i), this._montoya);
                        break;
                    default: // MessageType 1, 4: both are invocation messages with the same structure
                        message = new InvocationMessage(blazorMessages.getJSONObject(i), this._montoya);
                        break;
                }
                newBody.write(message.toBlazorBytes());
            }
        } catch (IOException e) {
            this.logging.logToError("[-] blazorPack - An error occurred writing blazor bytes to output stream: " + e.getMessage());
            return null;
        } catch (Exception e) {
            this.logging.logToError("[-] blazorPack - An unexpected error occurred: " + e.getMessage());
            return null;
        }
        return newBody.toByteArray();
    }

    /**
     * Perform Blazor Deserialization, from Blazor Bytes to JSON
     * @param blob - a byte array containing the blazor bytes to deserialize into JSON
     * @return - an arraylist of instantiated Message objects, containing deserialized representations of the messages
     */
    public ArrayList<GenericMessage> blazorUnpack(byte[] blob) {
        ArrayList<GenericMessage> messages = new ArrayList<>();
        try{
            int blobIdx = 0;
            int blobLength = blob.length;
            while (blobIdx < blobLength) {
                byte[] blobSlice = ArraySliceHelper.getArraySlice(blob, blobIdx, blobLength);
                JSONObject varInt = null;
                try {
                    varInt = VarIntHelper.extractVarInt(blobSlice);
                } catch (IOException e) {
                    this.logging.logToError("[-] blazorUnpack - An IOException occurred while unpacking the provided blob: " + e.getMessage());
                    return null;
                } catch (Exception e) {
                    this.logging.logToError("[-] blazorUnpack - An unexpected exception occurred while unpacking the blob: " + e.getMessage());
                    return null;
                }
                int bytesRead = varInt.getInt("bytesRead");
                int msgSize = varInt.getInt("result");
                byte[] messageBytes = ArraySliceHelper.getArraySlice(blob, blobIdx + bytesRead, blobIdx + bytesRead + msgSize);
                GenericMessage msg = initializeMessage(messageBytes);
                messages.add(msg);
                blobIdx += bytesRead + msgSize;
            }
        }catch(Exception e){
            messages.add(new DisplayErrorMessage("Message is incomplete or incompatible", _montoya));
        }

        return messages;
    }

    /**
     * Helper function to get the index of the body from a whole HTTP request/response
     * @param data - a byte array containing the whole HTTP request or response
     * @return - an integer representing the offset of the body within the request/response
     */
    public int getBodyOffset(byte[] data) {
        Matcher matcher = BTPConstants.BODY_OFFSET.matcher(new String(data, StandardCharsets.UTF_8));
        if (matcher.find()) {
            return matcher.end(); // Returns the index AFTER the matched characters, this is where the body starts
        }
        return 0;
    }

    /**
     * Instantiates a specific type of Message object given the raw message bytes
     * @param raw - a byte array containing the blazorpack bytes
     * @return an instantiated message object
     */
    private GenericMessage initializeMessage(byte[] raw) {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(raw);
        try {
            int arrayHeader = unpacker.unpackArrayHeader();
            if (arrayHeader == 0) {
                return null;
            }
            int msgType = unpacker.unpackInt();
            unpacker.close();
            switch (msgType) {
                case BTPConstants.STREAMITEM:
                    return new StreamItemMessage(raw, this._montoya);
                case BTPConstants.COMPLETION:
                    return new CompletionMessage(raw, this._montoya);
                case BTPConstants.CANCELINVOCATION:
                    return new CancelInvocationMessage(raw, this._montoya);
                case BTPConstants.PING:
                    return new PingMessage(raw, this._montoya);
                case BTPConstants.CLOSE:
                    return new CloseMessage(raw, this._montoya);
                default: // Cases 1,4 are InvocationMessage, StreamInvocation respectively. Both have the same format
                    return new InvocationMessage(raw, this._montoya);
            }
        } catch (IOException e) {
            this.logging.logToError("[-] initializeMessage - An IOException occurred while initializing the message: " + e.getLocalizedMessage());
        } catch (Exception e) {
            this.logging.logToError("[-] initializeMessage - An unexpected error occurred while initializing the message from the raw data: " + e.getMessage());
        }
        return null;
    }

    /**
     * Converts an arraylist of messages into a string representation of a JSON Array
     * @param messages - the arraylist of messages to convert
     * @return sb - a string containing the JSON representation of the messages
     */
    public String messageArrayToString(ArrayList<GenericMessage> messages) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < messages.size(); i++) {
            GenericMessage msg = messages.get(i);
            sb.append(msg.toJsonString());
            if (i != messages.size() - 1) {
                sb.append(",\r\n");
            }
        }
        sb.append("]");
        return sb.toString();
    }
}
