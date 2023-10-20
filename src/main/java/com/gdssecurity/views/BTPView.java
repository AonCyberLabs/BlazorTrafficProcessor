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
package com.gdssecurity.views;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.RawEditor;
import com.gdssecurity.MessageModel.GenericMessage;
import com.gdssecurity.helpers.BlazorHelper;
import org.json.JSONArray;
import org.json.JSONException;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

/**
 * Class to handle the new BTP Burpsuite Tab
 */
public class BTPView extends JComponent {

    private MontoyaApi _montoya;
    private Logging _logging;
    private JPanel topLevel;
    private JPanel mainView;
    private JPanel buttonView;
    private RawEditor editor;
    private RawEditor results;
    private JButton convertButton;
    private JButton clearButton;
    private String buttonText;
    private JComboBox<String> dropDownMenu;
    private BlazorHelper blazorHelper;
    private JCheckBox useWebSocketCheckBox;
    private final int DESERIALIZE_IDX = 0;
    private final int SERIALIZE_IDX = 1;

    /**
     * Constructor for the BTPView object
     * @param montoyaApi - an instance of the Burpsuite Montoya APIs
     */
    public BTPView(MontoyaApi montoyaApi) {
        setLayout(new BorderLayout(10, 10));
        this._montoya = montoyaApi;
        this._logging = montoyaApi.logging();
        this.blazorHelper = new BlazorHelper(this._montoya);
        this.buttonText = "Deserialize";
        this.topLevel = new JPanel();
        this.topLevel.setLayout(new BorderLayout(10, 10));
        this.mainView = new JPanel();
        this.mainView.setLayout(new GridLayout(1, 2));
        this.buttonView = new JPanel();
        this.buttonView.setLayout(new GridLayout(1, 3));

        // Editor, where the user input goes
        this.editor = this._montoya.userInterface().createRawEditor();
        this.mainView.add(this.editor.uiComponent());

        // Results, where the de/serialization output goes
        this.results = this._montoya.userInterface().createRawEditor();
        this.mainView.add(this.results.uiComponent());

        // Button, handle the serialize/deserialize actions
        this.convertButton = new JButton();
        this.convertButton.setText(this.buttonText);
        this.convertButton.addActionListener(e -> {
            this.handleButtonClick();
        });
        this.buttonView.add(this.convertButton);

        // Drop-down Menu, handle switching b/w Blazor->JSON & JSON->Blazor
        String[] menuItems = {"Blazor->JSON", "JSON->Blazor"};
        this.dropDownMenu = new JComboBox<String>(menuItems);
        this.dropDownMenu.addActionListener(e -> {
            this.handleSelectionChange();
        });
        this.buttonView.add(this.dropDownMenu);

        this.clearButton = new JButton();
        this.clearButton.setText("Clear");
        this.clearButton.addActionListener(e -> {
            this.editor.setContents(ByteArray.byteArray(""));
            this.results.setContents(ByteArray.byteArray(""));
        });
        this.buttonView.add(this.clearButton);

        this.useWebSocketCheckBox = new JCheckBox("Use WebSocket");
        Boolean useWebSocket = this._montoya.persistence().preferences().getBoolean("use_websocket");
        if(useWebSocket == null)
            useWebSocket = false; // default value
        this.useWebSocketCheckBox.setSelected(useWebSocket);
        this.useWebSocketCheckBox.addActionListener(e -> {
            this._montoya.persistence().preferences().setBoolean("use_websocket", this.useWebSocketCheckBox.isSelected());
        });
        this.buttonView.add(this.useWebSocketCheckBox);

        // Add the button view to main UI component
        this.topLevel.add(this.buttonView, BorderLayout.NORTH);

        // Add the main pane to the view
        this.topLevel.add(mainView, BorderLayout.CENTER);
        add(this.topLevel);
    }

    /**
     * Function to set the contents of the editor field
     * @param text - a ByteArray containing the text to populate the editor with
     */
    public void setEditorText(ByteArray text) {
        this.editor.setContents(text);
    }

    /**
     * Called when the drop-down menu item changes
     * Used for swapping the button label from Serialize <-> Deserialize
     */
    private void handleSelectionChange() {
        if (this.dropDownMenu.getSelectedIndex() == this.DESERIALIZE_IDX) {
            this.convertButton.setText("Deserialize");
        } else if (this.dropDownMenu.getSelectedIndex() == this.SERIALIZE_IDX) {
            this.convertButton.setText("Serialize");
        }
    }

    /**
     * Called when the button is clicked
     * Used for performing the serialization/deserialization and updating the results view
     */
    private void handleButtonClick() {
        // Check for content
        ByteArray content = this.editor.getContents();
        if (content == null || content.length() == 0) {
            this.results.setContents(ByteArray.byteArray("Error: editor input cannot be empty."));
            return;
        }

        // Check which option selected
        if (this.dropDownMenu.getSelectedIndex() == this.SERIALIZE_IDX) {
            try {
                JSONArray messages = new JSONArray(content.toString());
                byte[] blazorBytes = this.blazorHelper.blazorPack(messages);
                this.results.setContents(ByteArray.byteArray(blazorBytes));
            } catch (JSONException e) {
                this._logging.logToError("[-] handleButtonClick - An error occurred while parsing the provided JSON: " + e.getMessage());
                this.results.setContents(ByteArray.byteArray("Error while parsing provided JSON. Please pass a valid JSON array."));
            } catch (Exception e) {
                this._logging.logToError("[-] handleButtonClick - An error occurred during serialization: " + e.getMessage());
                this.results.setContents(ByteArray.byteArray("Error while parsing provided JSON. Please pass a valid JSON array."));
            }
        } else if (this.dropDownMenu.getSelectedIndex() == this.DESERIALIZE_IDX) {
            try {
                byte[] contentBytes = content.getBytes();
                ArrayList<GenericMessage> messages = this.blazorHelper.blazorUnpack(contentBytes);
                String messagesStr = this.blazorHelper.messageArrayToString(messages);
                this.results.setContents(ByteArray.byteArray(messagesStr));
            } catch (Exception e) {
                this._logging.logToError("[-] handleButtonClick - An error occurred during deserialization: " + e.getMessage());
                this.results.setContents(ByteArray.byteArray("Error while parsing provided blazor bytes."));
            }
        }
    }

}
