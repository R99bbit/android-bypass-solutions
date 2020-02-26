package okhttp3.internal.platform;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;
import javax.annotation.Nullable;
import javax.net.ssl.SSLSocket;
import okhttp3.Protocol;
import okhttp3.internal.Util;

class JdkWithJettyBootPlatform extends Platform {
    private final Class<?> clientProviderClass;
    private final Method getMethod;
    private final Method putMethod;
    private final Method removeMethod;
    private final Class<?> serverProviderClass;

    private static class JettyNegoProvider implements InvocationHandler {
        private final List<String> protocols;
        String selected;
        boolean unsupported;

        JettyNegoProvider(List<String> list) {
            this.protocols = list;
        }

        public Object invoke(Object obj, Method method, Object[] objArr) throws Throwable {
            String name = method.getName();
            Class<?> returnType = method.getReturnType();
            if (objArr == null) {
                objArr = Util.EMPTY_STRING_ARRAY;
            }
            if (name.equals("supports") && Boolean.TYPE == returnType) {
                return Boolean.valueOf(true);
            }
            if (name.equals("unsupported") && Void.TYPE == returnType) {
                this.unsupported = true;
                return null;
            } else if (name.equals("protocols") && objArr.length == 0) {
                return this.protocols;
            } else {
                if ((name.equals("selectProtocol") || name.equals("select")) && String.class == returnType && objArr.length == 1 && (objArr[0] instanceof List)) {
                    List list = (List) objArr[0];
                    int size = list.size();
                    for (int i = 0; i < size; i++) {
                        if (this.protocols.contains(list.get(i))) {
                            String str = (String) list.get(i);
                            this.selected = str;
                            return str;
                        }
                    }
                    String str2 = this.protocols.get(0);
                    this.selected = str2;
                    return str2;
                } else if ((!name.equals("protocolSelected") && !name.equals("selected")) || objArr.length != 1) {
                    return method.invoke(this, objArr);
                } else {
                    this.selected = (String) objArr[0];
                    return null;
                }
            }
        }
    }

    JdkWithJettyBootPlatform(Method method, Method method2, Method method3, Class<?> cls, Class<?> cls2) {
        this.putMethod = method;
        this.getMethod = method2;
        this.removeMethod = method3;
        this.clientProviderClass = cls;
        this.serverProviderClass = cls2;
    }

    /* JADX WARNING: type inference failed for: r8v0, types: [java.util.List<okhttp3.Protocol>, java.util.List] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public void configureTlsExtensions(SSLSocket sSLSocket, String str, List<Protocol> r8) {
        List<String> alpnProtocolNames = alpnProtocolNames(r8);
        try {
            Object newProxyInstance = Proxy.newProxyInstance(Platform.class.getClassLoader(), new Class[]{this.clientProviderClass, this.serverProviderClass}, new JettyNegoProvider(alpnProtocolNames));
            this.putMethod.invoke(null, new Object[]{sSLSocket, newProxyInstance});
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw Util.assertionError("unable to set alpn", e);
        }
    }

    public void afterHandshake(SSLSocket sSLSocket) {
        try {
            this.removeMethod.invoke(null, new Object[]{sSLSocket});
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw Util.assertionError("unable to remove alpn", e);
        }
    }

    @Nullable
    public String getSelectedProtocol(SSLSocket sSLSocket) {
        try {
            Object[] objArr = {sSLSocket};
            String str = null;
            JettyNegoProvider jettyNegoProvider = (JettyNegoProvider) Proxy.getInvocationHandler(this.getMethod.invoke(null, objArr));
            if (jettyNegoProvider.unsupported || jettyNegoProvider.selected != null) {
                if (!jettyNegoProvider.unsupported) {
                    str = jettyNegoProvider.selected;
                }
                return str;
            }
            Platform.get().log(4, "ALPN callback dropped: HTTP/2 is disabled. Is alpn-boot on the boot class path?", null);
            return null;
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw Util.assertionError("unable to get selected protocol", e);
        }
    }

    public static Platform buildIfSupported() {
        try {
            Class<?> cls = Class.forName("org.eclipse.jetty.alpn.ALPN");
            StringBuilder sb = new StringBuilder();
            sb.append("org.eclipse.jetty.alpn.ALPN");
            sb.append("$Provider");
            Class<?> cls2 = Class.forName(sb.toString());
            StringBuilder sb2 = new StringBuilder();
            sb2.append("org.eclipse.jetty.alpn.ALPN");
            sb2.append("$ClientProvider");
            Class<?> cls3 = Class.forName(sb2.toString());
            StringBuilder sb3 = new StringBuilder();
            sb3.append("org.eclipse.jetty.alpn.ALPN");
            sb3.append("$ServerProvider");
            Class<?> cls4 = Class.forName(sb3.toString());
            Method method = cls.getMethod("put", new Class[]{SSLSocket.class, cls2});
            Method method2 = method;
            JdkWithJettyBootPlatform jdkWithJettyBootPlatform = new JdkWithJettyBootPlatform(method2, cls.getMethod("get", new Class[]{SSLSocket.class}), cls.getMethod("remove", new Class[]{SSLSocket.class}), cls3, cls4);
            return jdkWithJettyBootPlatform;
        } catch (ClassNotFoundException | NoSuchMethodException unused) {
            return null;
        }
    }
}