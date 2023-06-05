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
package com.gdssecurity.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import com.gdssecurity.editors.BTPHttpResponseEditor;

/**
 * Class to implement an HTTPResponseEditorProvider, which will create new tabs on each BlazorPack response
 */
public class BTPHttpResponseEditorProvider implements HttpResponseEditorProvider {

    private MontoyaApi _montoya;

    /**
     * Construct a BTPHttpResponseEditorProvider
     * @param api - an instance of the Montoya API
     */
    public BTPHttpResponseEditorProvider(MontoyaApi api) {
        this._montoya = api;
    }

    /**
     * Returns a newly created HttpResponseEditor tab for each in-scope BlazorPack response.
     * @param editorContext       Context details about the editor.
     * @return the newly created editor object
     */
    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorContext) {
        return new BTPHttpResponseEditor(this._montoya, editorContext.editorMode());
    }
}
