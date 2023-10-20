# BlazorTrafficProcessor (BTP)
A BurpSuite extension to aid pentesting web applications that use Blazor Server/BlazorPack. Primary functionality includes converting BlazorPack messages to JSON and vice versa, introduces tamperability for BlazorPack serialized messages.

## Build

### Prerequisites
- Install [Java 19](https://www.oracle.com/java/technologies/javase/jdk19-archive-downloads.html) on your building machine.
- Install [Gradle](https://gradle.org/install/) on your building machine.
- Ensure the `JAVA_HOME` environment variable is set to the JDK 19 path if you have multiple versions of Java installed.
    - _NOTE: This project requires Java 17+._

### Build Steps
1. Clone the repository with `git clone https://github.com/AonCyberLabs/BlazorTrafficProcessor`
2. `cd BlazorTrafficProcessor`
3. `gradle build`
4. The built JAR file will be located at `./build/libs/` or `./releases/`

Note: The latest build should be automatically compiled by GitHub workflows (Actions)

## Usage

### Installing the extension in Burp 
* Download the latest `.jar` from the Releases page or build the project manually.
  * _The project has been submitted to the BApp store and is pending review_.
* Load the extension into Burp
  1. Click "Extender"
  2. Under "Extensions", click "Add"
  3. In the file selector, choose the downloaded/built `.jar` file

**NOTE: it is recommended to check "Other Binary" in your Burp History filter, this will allow you to see data returned by the application.**

### Using the Extension
* All BlazorPack-enabled requests or responses will be highlighted as Cyan within the "Http History" tab in Burpsuite.
* The "BTP" request/response editor tab, which appears on each in-scope request or response that contains BlazorPack messages. 
  * Clicking on this tab will convert the serialized data from BlazorPack to JSON.
  * After editing the JSON (either in Intercept or Repeater), click the "Raw" tab to re-serialize with your payloads
* The "BTP" Burpsuite tab, which allows for ad-hoc conversions of Blazor->JSON and JSON->Blazor
  * The left-hand editor is for your input (JSON or raw Blazor)
  * The right-hand editor is for the results of the conversion
  * A drop-down menu on the bottom of the window lets you select "Blazor->JSON" or "JSON->Blazor"
  * The Serialize/Deserialize button at the top is how you trigger the conversion
* Right-click menu option called "Send body to BTP tab"
  * You can right-click any request or response and select "Extensions" -> "BlazorTrafficProcessor" -> "Send body to BTP tab"
  * This sends either the selected request or response body to the BTP tab, so you don't have to worry about copying/pasting raw bytes

## Downgrade Explained (WS -> HTTP)
Blazor server normally communicates via WebSockets, though it supports other protocols such as LongPolling over HTTP.
During the connection initiation between your browser and the server, one of the first requests sent will look like the following:
```http
POST /_blazor/negotiate?negotiateVersion=1 HTTP/1.1
Host: localhost:5003
[...]
X-Requested-With: XMLHttpRequest
X-SignalR-User-Agent: Microsoft SignalR/0.0 (0.0.0-DEV_BUILD; Unknown OS; Browser; Unknown Runtime Version)
[...]
```

The response will contain the available transports as follows:
```http
HTTP/1.1 200 OK
Content-Length: 316
Connection: close
Content-Type: application/json
Date: Thu, 22 Sep 2022 13:30:17 GMT
Server: Kestrel

{"negotiateVersion":1,
  "connectionId":"XXX",
  "connectionToken":"XXX",
  "availableTransports":[
    {"transport":"WebSockets","transferFormats":["Text","Binary"]},
    {"transport":"ServerSentEvents","transferFormats":["Text"]},
    {"transport":"LongPolling","transferFormats":["Text","Binary"]}
  ]
}
```

This negotiation determines how the client and server will establish their connection. WebSockets is the preferred method but Burp previously didn't have the best support for WS extensions**, so we need to force the connection over HTTP in order to use the extension.
Therefore, the browser (and JavaScript running in it) that you're proxying traffic through will see that websockets aren't supported and fall back to using HTTP ("LongPolling").
BTP will automatically perform this downgrade, observable via the Original/Modified versions of the Blazor negotiation HTTP response.

** Note: Support for BlazorPack over WS is currently under development as there are newer iterations of Burp's Montoya APIs being released frequently with improved WS functionality.

## Example Requests

### Change value of an Input Field
Request Body:
```text
ºÀ·BeginInvokeDotNetFromJS¡2À²DispatchEventAsyncÙ[{"eventHandlerId":4,"eventName":"change","eventFieldInfo":{"componentId":27,"fieldValue":"asdfasdfasdf"}},{"value":"asdfasdfasdf"}]
```

Deserialized:
```json
[
  {
    "Target":"BeginInvokeDotNetFromJS",
    "Headers":0,
    "Arguments":[
      "2","null","DispatchEventAsync",1, [
        {"eventFieldInfo": {"componentId":27,"fieldValue":"asdfasdfasdf"}, 
        "eventHandlerId":4,"eventName":"change"},
        {"value":"asdfasdfasdf"}
      ]
    ],
  "MessageType":1
  }
]
```

### Update the rendered web page
Request body:
```text
À±OnRenderCompletedÀ
```

Deserialized:
```json
[
  {
    "Target":"OnRenderCompleted",
    "Headers":0,
    "Arguments":[5,"null"],
    "MessageType":1
  }
]
```

### End an invocation
Request body (What you'll see in Burp):
```text
+ÀµEndInvokeJSFromDotNetÃ­[3,true,null]
```

Request body bytes (What you'll see in the "Inspector" tab if you highlight the request body)
```text
\x2b\x95\x01\x80\xc0\xb5EndInvokeJSFromDotNet\x93\x03\xc3\xad[3,true,null]
[length][MessageType,Headers,InvocationId,Target,[Arguments]]
[\x2b][MessageType=\x01,Headers=\x80,InvocationId=\xc0,Target=\xb5EndInvokeJSFromDotNet,Arguments=[One=\x03,Two=\xc3,Three=\xad[3,true,null]]]
```

#### Byte Breakdown
_[InvocationMessage Encoding Spec](https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#invocation-message-encoding-1)_

1. `\x2b` - the size byte for this payload, value = 43
   * [CyberChef Formula](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')VarInt_Decode()&input=MmI)
2. `\x95` - an array header, representing a 5-element array
3. `\x01` - integer w/ value of 1, representing the message type (Invocation)
4. `\x80` - Map of length 0, representing the headers (only seen empty map while testing)
5. `\xc0` - NIL, representing the invocationId is null
6. `\xb5` - Raw string header of length 21, representing the "Target"
7. `EndInvokeJSFromDotNet` - the "Target" raw string
8. `\x93` - an array header, representing a 3-element array for the arguments
9. `\x03` - integer w/ value of 3, first argument to the "Target" function
10. `\xc3` - boolean w/ value of true, second argument to the "Target" function
11. `\xad` - Raw string header of length 13, representing the third argument to the "Target" function
12. `[3,true,null]` - the third argument raw string

Deserialized:
```json
[
  {
    "Target":"EndInvokeJSFromDotNet",
    "Headers":0,
    "Arguments": [
      3,true,
      [3,true,null]
    ],
    "MessageType":1
  }
]
```

#### Contributors

SignalR header support added by [@R4ML1N](https://github.com/R4ML1N)

WebSocket support has been added by Soroush Dalili [@irsdl](https://github.com/irsdl)


#### Copyright

Copyright 2023 Aon plc
