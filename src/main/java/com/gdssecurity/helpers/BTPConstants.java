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

import org.json.JSONArray;

import java.util.regex.Pattern;

/**
 * Class holding all BTP constants
 */
public final class BTPConstants {
    // Label and UI Strings
    public static final String EXTENSION_NAME = "BlazorTrafficProcessor";
    public static final String CAPTION = "BTP";
    public static final String SEND_TO_BTP_CAPTION = "Send body to BTP tab";
    public static final String SEND_TO_INT_CAPTION = "Send to Intruder";
    public static final String LOADED_LOG_MSG = "[+] BTP v1.1 Extension loaded.";
    public static final String UNLOADED_LOG_MSG = "[*] BTP v1.1 Extension unloaded.";

    // Patterns and Regexes
    public static final String BLAZOR_URL = "_blazor?id=";
    public static final String NEGOTIATE_URL = "negotiate?negotiateVersion=";
    public static final Pattern BODY_OFFSET = Pattern.compile("(\r\n\r\n)");
    public static final String HEX_FORMAT = "%02X";
    public static final String SIGNALR_HEADER = "X-Signalr-User-Agent";

    // Downgrade Constants (WS -> HTTP)
    public static final String TRANSPORT_STR = "[{'transport':'ServerSentEvents','transferFormats':['Text']},{'transport':'LongPolling','transferFormats':['Text','Binary']}]";
    public static final JSONArray DOWNGRADED_TRANSPORTS = new JSONArray(TRANSPORT_STR);

    // HubProtocol Constants
    public static final int INVOCATION = 1;
    public static final int STREAMITEM = 2;
    public static final int COMPLETION = 3;
    public static final int STREAMINVOCATION = 4;
    public static final int CANCELINVOCATION = 5;
    public static final int PING = 6;
    public static final int CLOSE = 7;
    public static final int CANCEL_INVOCATION_ARRAY_HEADER = 3;
    public static final int CLOSE_RECONNECT_ARRAY_HEADER = 3;
    public static final int CLOSE_NORECON_ARRAY_HEADER = 2;
    public static final int COMPLETION_RESULT_HEADER = 5;
    public static final int COMPLETION_NORES_HEADER = 4;
    public static final int RESULT_KIND_ERROR = 1;
    public static final int RESULT_KIND_VOID = 2;
    public static final int RESULT_KIND_NONVOID = 3;
    public static final int DEFAULT_MAP_HEADER = 0;
    public static final int INVOCATION_ARRAY_HEADER = 5;
}
