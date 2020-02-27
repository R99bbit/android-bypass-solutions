package com.github.nkzawa.socketio.client;

import com.github.nkzawa.socketio.parser.Parser;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

public class IO {
    private static final Logger logger = Logger.getLogger(IO.class.getName());
    private static final ConcurrentHashMap<String, Manager> managers = new ConcurrentHashMap<>();
    public static int protocol = Parser.protocol;

    public static class Options extends com.github.nkzawa.socketio.client.Manager.Options {
        public boolean forceNew;
        public boolean multiplex = true;
    }

    public static void setDefaultSSLContext(SSLContext sslContext) {
        Manager.defaultSSLContext = sslContext;
    }

    public static void setDefaultHostnameVerifier(HostnameVerifier hostnameVerifier) {
        Manager.defaultHostnameVerifier = hostnameVerifier;
    }

    private IO() {
    }

    public static Socket socket(String uri) throws URISyntaxException {
        return socket(uri, (Options) null);
    }

    public static Socket socket(String uri, Options opts) throws URISyntaxException {
        return socket(new URI(uri), opts);
    }

    public static Socket socket(URI uri) {
        return socket(uri, (Options) null);
    }

    public static Socket socket(URI uri, Options opts) {
        Manager io2;
        if (opts == null) {
            opts = new Options();
        }
        URL parsed = Url.parse(uri);
        try {
            URI source = parsed.toURI();
            if (opts.forceNew || !opts.multiplex) {
                logger.fine(String.format("ignoring socket cache for %s", new Object[]{source}));
                io2 = new Manager(source, opts);
            } else {
                String id = Url.extractId(parsed);
                if (!managers.containsKey(id)) {
                    logger.fine(String.format("new io instance for %s", new Object[]{source}));
                    managers.putIfAbsent(id, new Manager(source, opts));
                }
                io2 = managers.get(id);
            }
            return io2.socket(parsed.getPath());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }
}