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
package com.gdssecurity.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.gdssecurity.MessageModel.GenericMessage;
import com.gdssecurity.helpers.ArraySliceHelper;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.BlazorHelper;
import org.json.JSONArray;
import org.json.JSONException;

import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/**
 * Class to implement the "BTP" editor tab for HTTP requests
 */
public class BTPHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private MontoyaApi _montoya;
    private HttpRequestResponse reqResp;
    private RawEditor editor;
    private BlazorHelper blazorHelper;
    private Logging logging;

    /**
     * Constructs a new BTPHttpRequestEditor object
     * @param api - an instance of the Montoya API
     * @param editorMode - options for the editor object
     */
    public BTPHttpRequestEditor(MontoyaApi api, EditorMode editorMode) {
        this._montoya = api;
        this.editor = this._montoya.userInterface().createRawEditor();
        this.blazorHelper = new BlazorHelper(this._montoya);
        this.logging = this._montoya.logging();
    }

    /**
     * Converts a JSON message to BlazorPack, called when the "Raw" tab is clicked
     * Just return the existing request body if editor not modified, re-serialize if editor is modified
     * @return - an HttpRequest object containing the BlazorPacked HTTP request/response pair
     */
    @Override
    public HttpRequest getRequest() {
        byte[] body;
        if (this.editor.isModified()) {
            int bodyOffset = this.blazorHelper.getBodyOffset(this.editor.getContents().getBytes());
            body = ArraySliceHelper.getArraySlice(this.editor.getContents().getBytes(), bodyOffset, this.editor.getContents().length());
        } else {
            body = this.reqResp.request().body().getBytes();
        }
        if (body == null | body.length == 0) {
            this.logging.logToError("[-] getRequest: The selected editor body is empty/null.");
            return null;
        }
        JSONArray messages;
        byte[] newBody;
        try {
            messages = new JSONArray(new String(body));
            newBody = this.blazorHelper.blazorPack(messages);
        } catch (JSONException e) {
            this.logging.logToError("[-] getRequest - JSONExcpetion while parsing JSON array: " + e.getMessage());
            return null;
        } catch (Exception e) {
            this.logging.logToError("[-] getRequest - Unexpected exception while getting the request: " + e.getMessage());
            return null;
        }
        return this.reqResp.request().withBody(ByteArray.byteArray(newBody));
    }

    /**
     * Converts a given BlazorPack message to JSON, called when the "BTP" tab is clicked
     * @param requestResponse - The request to deserialize from BlazorPack to JSON
     */
    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.reqResp = requestResponse;
        byte[] body = requestResponse.request().body().getBytes();
        ArrayList<GenericMessage> messages = this.blazorHelper.blazorUnpack(body);
        ByteArrayOutputStream outstream = new ByteArrayOutputStream();
        try {
            String jsonStrMessages = this.blazorHelper.messageArrayToString(messages);
            outstream.write(jsonStrMessages.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            this.logging.logToError("[-] setRequestResponse - IOException while writing bytes to buffer: " + e.getMessage());
            return;
        } catch (JSONException e) {
            this.logging.logToError("[-] setRequestResponse - JSONException while parsing JSON array: " + e.getMessage());
            return;
        } catch (Exception e) {
            this.logging.logToError("[-] setRequestResponse - Unexpected exception: " + e.getMessage());
            return;
        }
        HttpRequest newReq = this.reqResp.request().withBody(ByteArray.byteArray(outstream.toByteArray()));
        this.reqResp = HttpRequestResponse.httpRequestResponse(newReq, this.reqResp.response());
        this.editor.setContents(this.reqResp.request().toByteArray());
    }

    /**
     * Checks to see if the "BTP" tab should appear on a given request
     * @param requestResponse - the HTTP request/response pair object to check.
     * @return true if it should be enabled, false otherwise
     */
    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return false;
        }

        if (requestResponse.request().httpVersion() == null) {
            return false;
        }

        if (requestResponse.request().url() == null) {
            return false;
        }

        if (!this._montoya.scope().isInScope(requestResponse.request().url())) {
            return false;
        }

        if (requestResponse.request().contentType() == ContentType.JSON) {
            return false;
        }

        if (!requestResponse.request().url().contains(BTPConstants.BLAZOR_URL)) {
            if (!requestResponse.request().hasHeader(BTPConstants.SIGNALR_HEADER)) {
                return false;
            }
        }

        if (requestResponse.request().body() == null || requestResponse.request().body().length() == 0) {
            return false;
        }

        // Request during negotiation containing "{anything}\x1e", not valid blazor and BTP tab shouldn't be enabled
        if (requestResponse.request().body().toString().startsWith("{") && requestResponse.request().body().toString().endsWith("}\u001E")) {
            return false;
        }

        return true;
    }

    /**
     * Gets the caption for the editor tab
     * @return "BTP" - BlazorTrafficProcessor
     */
    @Override
    public String caption() {
        return BTPConstants.CAPTION;
    }

    /**
     * Gets the UI component for the editor tab
     * @return the editor's UI component
     */
    @Override
    public Component uiComponent() {
        return this.editor.uiComponent();
    }

    /**
     * Get the selected data within the editor
     * @return the editor's selection object
     */
    @Override
    public Selection selectedData() {
        return this.editor.selection().get();
    }

    /**
     * Check if the editor has been modified. If not, the getHttpRequest function is not called.
     * @return true if modified, false otherwise
     */
    @Override
    public boolean isModified() {
        return this.editor.isModified();
    }
}
