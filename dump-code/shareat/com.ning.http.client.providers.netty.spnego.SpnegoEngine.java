package com.ning.http.client.providers.netty.spnego;

import com.ning.http.util.Base64;
import java.io.IOException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SpnegoEngine {
    private static final String KERBEROS_OID = "1.2.840.113554.1.2.2";
    private static final String SPNEGO_OID = "1.3.6.1.5.5.2";
    private GSSContext gssContext;
    private final Logger log;
    private Oid negotiationOid;
    private final SpnegoTokenGenerator spnegoGenerator;
    private byte[] token;

    public SpnegoEngine(SpnegoTokenGenerator spnegoGenerator2) {
        this.log = LoggerFactory.getLogger((Class) getClass());
        this.gssContext = null;
        this.negotiationOid = null;
        this.spnegoGenerator = spnegoGenerator2;
    }

    public SpnegoEngine() {
        this(null);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:28:0x0101, code lost:
        r0 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x010b, code lost:
        throw new java.lang.Exception(r0.getMessage());
     */
    /* JADX WARNING: Removed duplicated region for block: B:28:0x0101 A[ExcHandler: IOException (r0v0 'ex' java.io.IOException A[CUSTOM_DECLARE]), Splitter:B:0:0x0000] */
    public String generateToken(String server) throws Throwable {
        boolean tryKerberos;
        try {
            this.log.debug((String) "init {}", (Object) server);
            this.negotiationOid = new Oid(SPNEGO_OID);
            tryKerberos = false;
            GSSManager manager = GSSManager.getInstance();
            this.gssContext = manager.createContext(manager.createName("HTTP@" + server, GSSName.NT_HOSTBASED_SERVICE).canonicalize(this.negotiationOid), this.negotiationOid, null, 0);
            this.gssContext.requestMutualAuth(true);
            this.gssContext.requestCredDeleg(true);
        } catch (GSSException ex) {
            this.log.error((String) "generateToken", (Throwable) ex);
            if (ex.getMajor() == 2) {
                this.log.debug("GSSException BAD_MECH, retry with Kerberos MECH");
                tryKerberos = true;
            } else {
                throw ex;
            }
        } catch (IOException ex2) {
        } catch (GSSException gsse) {
            this.log.error((String) "generateToken", (Throwable) gsse);
            if (gsse.getMajor() == 9 || gsse.getMajor() == 8) {
                throw new Exception(gsse.getMessage(), gsse);
            } else if (gsse.getMajor() == 13) {
                throw new Exception(gsse.getMessage(), gsse);
            } else if (gsse.getMajor() == 10 || gsse.getMajor() == 19 || gsse.getMajor() == 20) {
                throw new Exception(gsse.getMessage(), gsse);
            } else {
                throw new Exception(gsse.getMessage());
            }
        }
        if (tryKerberos) {
            this.log.debug((String) "Using Kerberos MECH {}", (Object) KERBEROS_OID);
            this.negotiationOid = new Oid(KERBEROS_OID);
            GSSManager manager2 = GSSManager.getInstance();
            this.gssContext = manager2.createContext(manager2.createName("HTTP@" + server, GSSName.NT_HOSTBASED_SERVICE).canonicalize(this.negotiationOid), this.negotiationOid, null, 0);
            this.gssContext.requestMutualAuth(true);
            this.gssContext.requestCredDeleg(true);
        }
        if (this.token == null) {
            this.token = new byte[0];
        }
        this.token = this.gssContext.initSecContext(this.token, 0, this.token.length);
        if (this.token == null) {
            throw new Exception("GSS security context initialization failed");
        }
        if (this.spnegoGenerator != null && this.negotiationOid.toString().equals(KERBEROS_OID)) {
            this.token = this.spnegoGenerator.generateSpnegoDERObject(this.token);
        }
        this.gssContext.dispose();
        String tokenstr = new String(Base64.encode(this.token));
        this.log.debug((String) "Sending response '{}' back to the server", (Object) tokenstr);
        return tokenstr;
    }
}