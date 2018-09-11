package burp;

import java.io.PrintWriter;
import java.util.Random;
import java.util.List;
import java.net.URL;


public class BurpExtender implements burp.IBurpExtender, burp.IHttpListener
{
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private int counter = 0;
    private Boolean counterStarted = false;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // set our extension name
        callbacks.setExtensionName("IncrementURLNumber");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {
        // only process requests
        if (messageIsRequest) {
            // get the HTTP service for the request
            burp.IHttpService httpService = messageInfo.getHttpService();
            burp.IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);

            String request = new String(messageInfo.getRequest());

            List<String> headers = iRequest.getHeaders();
            
            String reqBody = request.substring(iRequest.getBodyOffset());
            
            String reqURL = headers.get(0);
                        
            if (reqURL.contains("IncrementURLNumber")) {
              
              String[] parts = reqURL.split("/");
              String lastPart = parts[parts.length-1];
              String[] lastPartSplit = lastPart.split("\\.");
              int firstNumber = Integer.parseInt(lastPartSplit[0]);
                            
              if(!counterStarted){
                counter = firstNumber;
                counterStarted = true;
              }
              
              counter++;
              stdout.println("-----Before-------");
              stdout.println(reqURL);
              
              reqURL = reqURL.replaceAll("IncrementURLNumber\\/.", "\\/" + counter);
              headers.set(0, reqURL);
              stdout.println("-----After-------");
              stdout.println(reqURL);
              stdout.println("");
              stdout.println("");
              
              byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
              messageInfo.setRequest(message);
              
            }

        }
    }
}
