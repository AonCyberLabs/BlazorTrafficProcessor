package com.gdssecurity.MessageModel;

import burp.api.montoya.MontoyaApi;
import com.gdssecurity.helpers.BTPConstants;
import org.json.JSONObject;

import java.io.IOException;

public class DisplayErrorMessage extends GenericMessage {
    public DisplayErrorMessage(String msg, MontoyaApi api) {
        super(new JSONObject().put(BTPConstants.EXTENSION_NAME + " Error", msg), api);
    }
    public DisplayErrorMessage(JSONObject msg, MontoyaApi api) {
        super(msg, api);
    }

    @Override
    boolean validateJson(JSONObject msg) {
        return true;
    }

    @Override
    void initBlazorFromJson() throws IOException {

    }

    @Override
    void initJsonFromMessage() throws IOException {

    }
}
