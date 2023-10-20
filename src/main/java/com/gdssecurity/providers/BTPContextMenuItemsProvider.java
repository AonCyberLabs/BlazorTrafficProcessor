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
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.BlazorHelper;
import com.gdssecurity.views.BTPView;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Class to handle the menu items in the right-click window under "Extensions"
 */
public class BTPContextMenuItemsProvider implements ContextMenuItemsProvider {

    private MontoyaApi _montoya;
    private Logging _logging;
    private BTPView btpTab;
    private BlazorHelper blazorHelper;

    /**
     * Construct an instance of the menu provider
     * @param montoyaApi - an instance of the Burpsuite Montoya APIs
     * @param btpTab - an instance of the BTP view, used to send the contents to BTP tab
     */
    public BTPContextMenuItemsProvider(MontoyaApi montoyaApi, BTPView btpTab) {
        this._montoya = montoyaApi;
        this._logging = montoyaApi.logging();
        this.blazorHelper = new BlazorHelper(this._montoya);
        this.btpTab = btpTab;
    }

    /**
     * Gets called by Burpsuite since this is a registered menu items provider
     * @param event This object can be queried to find out about HTTP request/responses that are associated with the context menu invocation.
     *
     * @return - an arraylist of components to include in the right-click menu
     */
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        ArrayList<Component> menuItems = new ArrayList<>();

        // Send to BTP tab for ad-hoc serialization
        JMenuItem sendToBTP = new JMenuItem();
        sendToBTP.setText(BTPConstants.SEND_TO_BTP_CAPTION);
        sendToBTP.addActionListener(e -> {
            HttpRequestResponse selection;
            // Selected inside the HTTP request/response editor
            if (event.selectedRequestResponses().isEmpty() && event.messageEditorRequestResponse().isPresent()) {
                selection = event.messageEditorRequestResponse().get().requestResponse();
            } else { // Selected on the request/response entry in HTTP history
                selection = event.selectedRequestResponses().get(0);
            }
            this.sendSelectionToBTP(selection);
        });
        menuItems.add(sendToBTP);
        return menuItems;
    }

    /**
     * Gets called by Burpsuite since this is a registered menu items provider
     * @param event This object can be queried to find out about HTTP websocket that are associated with the context menu invocation.
     *
     * @return - an arraylist of components to include in the right-click menu
     */
    public List<Component> provideMenuItems(WebSocketContextMenuEvent event) {
        ArrayList<Component> menuItems = new ArrayList<>();

        // Send to BTP tab for ad-hoc serialization
        JMenuItem sendToBTP = new JMenuItem();
        sendToBTP.setText(BTPConstants.SEND_TO_BTP_CAPTION);
        sendToBTP.addActionListener(e -> {
            WebSocketMessage selection;

            if(event.selectedWebSocketMessages().isEmpty() && event.messageEditorWebSocket().isPresent()){
                selection = event.messageEditorWebSocket().get().webSocketMessage();
            }else{ // Selected on WS history
                selection = event.selectedWebSocketMessages().get(0);
            }

            this.sendSelectionToBTP(selection);
        });
        menuItems.add(sendToBTP);
        return menuItems;
    }
    /**
     * Handles the selection of "Send body to BTP tab" menu option
     * Sends the body from the selected request/response to editor of BTP tab
     * @param selection - the selected HttpRequestResponse object
     */
    private void sendSelectionToBTP(HttpRequestResponse selection) {
        if (selection.request().url() != null && !selection.request().url().contains(BTPConstants.BLAZOR_URL)) {
            if (!selection.request().hasHeader(BTPConstants.SIGNALR_HEADER)) {
                this._logging.logToError("[-] sendSelectionToBTP - Selected message is not BlazorPack.");
                return;
            }
        }
        if (selection.request() != null && selection.request().body() != null && selection.request().body().length() != 0) {
            this.btpTab.setEditorText(selection.request().body());
        } else if (selection.response() != null && selection.response().body() != null && selection.response().body().length() != 0) {
            this.btpTab.setEditorText(selection.response().body());
        }
    }

    private void sendSelectionToBTP(WebSocketMessage selection) {
        if (selection.upgradeRequest().url() != null && !selection.upgradeRequest().url().contains(BTPConstants.BLAZOR_URL)) {
            if (!selection.upgradeRequest().hasHeader(BTPConstants.SIGNALR_HEADER)) {
                this._logging.logToError("[-] sendSelectionToBTP - Selected message is not BlazorPack.");
                return;
            }
        }

        this.btpTab.setEditorText(selection.payload());
    }

}
