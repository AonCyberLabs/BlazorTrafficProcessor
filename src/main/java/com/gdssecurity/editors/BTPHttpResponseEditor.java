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
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.gdssecurity.MessageModel.GenericMessage;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.BlazorHelper;

import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/**
 * Class to implement the "BTP" editor tab for HTTP responses
 */
public class BTPHttpResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private MontoyaApi _montoya;
    private Logging logging;
    private HttpRequestResponse reqResp;
    private RawEditor editor;
    private BlazorHelper blazorHelper;

    /**
     * Constructs a new BTPHttpResponseEditor based on a given message
     * @param api - instance of the MontoyaAPI
     * @param editorMode - options for the editor object
     */
    public BTPHttpResponseEditor(MontoyaApi api, EditorMode editorMode) {
        this._montoya = api;
        this.logging = this._montoya.logging();
        this.editor = this._montoya.userInterface().createRawEditor();
        this.blazorHelper = new BlazorHelper(this._montoya);
    }

    /**
     * Returns the raw HTTP response, called when "Raw" tab is clicked
     * No need to re-serialize since, editing responses is not supported (yet)
     * @return - the HttpResponse object directly from the class variable, no need for conversion - not editing responses.
     */
    @Override
    public HttpResponse getResponse() {
        return this.reqResp.response();
    }

    /**
     * Converts the provided HTTP response from BlazorPack to JSON, called when "BTP" tab is clicked
     * @param requestResponse - The response to deserialize from BlazorPack to JSON
     */
    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.reqResp = requestResponse;
        byte[] body = requestResponse.response().body().getBytes();
        ArrayList<GenericMessage> messages = this.blazorHelper.blazorUnpack(body);
        ByteArrayOutputStream outstream = new ByteArrayOutputStream();
        try {
            String jsonStrMessages = this.blazorHelper.messageArrayToString(messages);
            outstream.write(jsonStrMessages.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            this.logging.logToError("[-] setRequestResponse - IOException while writing bytes to buffer: " + e.getMessage());
            this.editor.setContents(ByteArray.byteArray("An error occurred while converting Blazor to JSON."));
            return;
        } catch (Exception e) {
            this.logging.logToError("[-] setRequestResponse - Unexpected exception occurred: ");
            this.editor.setContents(ByteArray.byteArray("An error occurred while converting Blazor to JSON."));
            return;
        }
        this.editor.setContents(this.reqResp.response().withBody(ByteArray.byteArray(outstream.toByteArray())).toByteArray());
    }

    /**
     * Check if the editor tab should be enabled for a given response.
     * @param requestResponse - the HTTP request/response pair to check.
     * @return true if it should be enabled, false otherwise
     */
    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.response() == null) {
            return false;
        }

        if (requestResponse.response().httpVersion() == null) {
            return false;
        }

        if (this._montoya.scope() == null) {
            return false;
        }

        if (requestResponse.response().httpVersion() == null) {
            return false;
        }

        if (!requestResponse.request().url().contains(BTPConstants.BLAZOR_URL)) {
            if (!requestResponse.request().hasHeader(BTPConstants.SIGNALR_HEADER)) {
                return false;
            }
        }

        if (!this._montoya.scope().isInScope(requestResponse.request().url())) {
            return false;
        }

        if (requestResponse.response().body() == null || requestResponse.response().body().length() == 0) {
            return false;
        }

        // Response during negotiation containing "{}\x1e", not valid blazor and BTP tab shouldn't be enabled
        if ( requestResponse.response().body().length() == 3 && requestResponse.response().body().toString().startsWith("{}")) {
            return false;
        }

        // Response during negotiation containing "{anything}\x1e", not valid blazor and BTP tab shouldn't be enabled
        if (requestResponse.response().body().toString().startsWith("{") && requestResponse.response().body().toString().endsWith("}\u001E")) {
            return false;
        }

        return true;
    }

    /**
     * Gets the caption for the response editor tab
     * @return "BTP" - BlazorTrafficProcessor
     */
    @Override
    public String caption() {
        return BTPConstants.CAPTION;
    }

    /**
     * Gets the UI component of the editor
     * @return the UI component directly from the editor class variable
     */
    @Override
    public Component uiComponent() {
        return this.editor.uiComponent();
    }

    /**
     * Gets the data selected in the editor
     * @return - the selected data
     */
    @Override
    public Selection selectedData() {
        return this.editor.selection().get();
    }

    /**
     * Checks if the editor text has been modified
     * @return true if it has, false otherwise
     */
    @Override
    public boolean isModified() {
        return this.editor.isModified();
    }
}
