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
package com.gdssecurity.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import com.gdssecurity.helpers.BTPConstants;

/**
 * Class to handle highlighting requests that use BlazorPack
 */
public class BTPHttpRequestHandler implements ProxyRequestHandler {

    private MontoyaApi _montoya;
    private Logging _logging;

    /**
     * Constructor for the request handler object
     * @param montoyaApi - an instance of the Burp Montoya APIs
     */
    public BTPHttpRequestHandler(MontoyaApi montoyaApi) {
        this._montoya = montoyaApi;
        this._logging = montoyaApi.logging();
    }

    /**
     * Handle the highlighting of requests when they are received
     * Note: only used for highlighting, no processing logic present
     * @param interceptedRequest - An object holding the captured HTTP request
     * @return - the intercepted request with an added highlight for requests that use BlazorPack
     */
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (interceptedRequest.body().length() != 0 && interceptedRequest.path().contains("_blazor?id")) {
            interceptedRequest.annotations().setHighlightColor(HighlightColor.CYAN);
        }
        if (interceptedRequest.hasHeader(BTPConstants.SIGNALR_HEADER)) {
            interceptedRequest.annotations().setHighlightColor(HighlightColor.CYAN);
        }
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    /**
     * Handle the request after it is received, before sent back to the client
     * Note: not utilized for this handler
     * @param interceptedRequest - An object holding the HTTP request right before it is sent
     * @return - an un-modified request
     */
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
}
