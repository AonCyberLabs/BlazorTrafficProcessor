package com.gdssecurity.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;
import com.gdssecurity.editors.BTPWebSocketEditor;

public class BTPWebSocketEditorProvider implements WebSocketMessageEditorProvider {

    private MontoyaApi _montoya;


    /**
     * Construct a BTPHttpResponseEditorProvider
     * @param api - an instance of the Montoya API
     */
    public BTPWebSocketEditorProvider(MontoyaApi api) {
        this._montoya = api;
    }

    /**
     * Invoked by Burp when a new Web Socket message editor is required from the extension.
     *
     * @param creationContext details about the context that is requiring a message editor
     * @return An instance of {@link ExtensionProvidedWebSocketMessageEditor}
     */
    @Override
    public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext creationContext) {
        return new BTPWebSocketEditor(this._montoya, creationContext.editorMode());
    }
}
