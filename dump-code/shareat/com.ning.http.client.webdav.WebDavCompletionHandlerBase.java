package com.ning.http.client.webdav;

import com.ning.http.client.AsyncCompletionHandlerBase;
import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public abstract class WebDavCompletionHandlerBase<T> implements AsyncHandler<T> {
    private final List<HttpResponseBodyPart> bodies = Collections.synchronizedList(new ArrayList());
    private HttpResponseHeaders headers;
    private final Logger logger = LoggerFactory.getLogger(AsyncCompletionHandlerBase.class);
    private HttpResponseStatus status;

    private class HttpStatusWrapper extends HttpResponseStatus {
        private final int statusCode;
        private final String statusText;
        private final HttpResponseStatus wrapper;

        public HttpStatusWrapper(HttpResponseStatus wrapper2, String statusText2, int statusCode2) {
            super(wrapper2.getUrl(), wrapper2.provider());
            this.wrapper = wrapper2;
            this.statusText = statusText2;
            this.statusCode = statusCode2;
        }

        public int getStatusCode() {
            return this.statusText == null ? this.wrapper.getStatusCode() : this.statusCode;
        }

        public String getStatusText() {
            return this.statusText == null ? this.wrapper.getStatusText() : this.statusText;
        }

        public String getProtocolName() {
            return this.wrapper.getProtocolName();
        }

        public int getProtocolMajorVersion() {
            return this.wrapper.getProtocolMajorVersion();
        }

        public int getProtocolMinorVersion() {
            return this.wrapper.getProtocolMinorVersion();
        }

        public String getProtocolText() {
            return this.wrapper.getStatusText();
        }
    }

    public abstract T onCompleted(WebDavResponse webDavResponse) throws Exception;

    public final STATE onBodyPartReceived(HttpResponseBodyPart content) throws Exception {
        this.bodies.add(content);
        return STATE.CONTINUE;
    }

    public final STATE onStatusReceived(HttpResponseStatus status2) throws Exception {
        this.status = status2;
        return STATE.CONTINUE;
    }

    public final STATE onHeadersReceived(HttpResponseHeaders headers2) throws Exception {
        this.headers = headers2;
        return STATE.CONTINUE;
    }

    public final T onCompleted() throws Exception {
        if (this.status != null) {
            Response response = this.status.provider().prepareResponse(this.status, this.headers, this.bodies);
            Document document = null;
            if (this.status.getStatusCode() == 207) {
                document = readXMLResponse(response.getResponseBodyAsStream());
            }
            return onCompleted(new WebDavResponse(this.status.provider().prepareResponse(this.status, this.headers, this.bodies), document));
        }
        throw new IllegalStateException("Status is null");
    }

    public void onThrowable(Throwable t) {
        this.logger.debug(t.getMessage(), t);
    }

    private Document readXMLResponse(InputStream stream) {
        try {
            Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stream);
            parse(document);
            return document;
        } catch (SAXException e) {
            this.logger.error(e.getMessage(), (Throwable) e);
            throw new RuntimeException(e);
        } catch (IOException e2) {
            this.logger.error(e2.getMessage(), (Throwable) e2);
            throw new RuntimeException(e2);
        } catch (ParserConfigurationException e3) {
            this.logger.error(e3.getMessage(), (Throwable) e3);
            throw new RuntimeException(e3);
        }
    }

    private void parse(Document document) {
        NodeList statusNode = document.getDocumentElement().getElementsByTagName("status");
        for (int i = 0; i < statusNode.getLength(); i++) {
            String value = statusNode.item(i).getFirstChild().getNodeValue();
            int statusCode = Integer.valueOf(value.substring(value.indexOf(" "), value.lastIndexOf(" ")).trim()).intValue();
            this.status = new HttpStatusWrapper(this.status, value.substring(value.lastIndexOf(" ")), statusCode);
        }
    }
}