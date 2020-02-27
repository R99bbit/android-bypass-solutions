package org.jboss.netty.handler.codec.http;

import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

public class DefaultCookie implements Cookie {
    private String comment;
    private String commentUrl;
    private boolean discard;
    private String domain;
    private boolean httpOnly;
    private int maxAge = Integer.MIN_VALUE;
    private final String name;
    private String path;
    private Set<Integer> ports = Collections.emptySet();
    private boolean secure;
    private Set<Integer> unmodifiablePorts = this.ports;
    private String value;
    private int version;

    public DefaultCookie(String name2, String value2) {
        if (name2 == null) {
            throw new NullPointerException("name");
        }
        String name3 = name2.trim();
        if (name3.length() == 0) {
            throw new IllegalArgumentException("empty name");
        }
        int i = 0;
        while (i < name3.length()) {
            char c = name3.charAt(i);
            if (c > 127) {
                throw new IllegalArgumentException("name contains non-ascii character: " + name3);
            }
            switch (c) {
                case 9:
                case 10:
                case 11:
                case 12:
                case 13:
                case ' ':
                case ',':
                case ';':
                case '=':
                    throw new IllegalArgumentException("name contains one of the following prohibited characters: =,; \\t\\r\\n\\v\\f: " + name3);
                default:
                    i++;
            }
        }
        if (name3.charAt(0) == '$') {
            throw new IllegalArgumentException("name starting with '$' not allowed: " + name3);
        }
        this.name = name3;
        setValue(value2);
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    public void setValue(String value2) {
        if (value2 == null) {
            throw new NullPointerException(Param.VALUE);
        }
        this.value = value2;
    }

    public String getDomain() {
        return this.domain;
    }

    public void setDomain(String domain2) {
        this.domain = validateValue("domain", domain2);
    }

    public String getPath() {
        return this.path;
    }

    public void setPath(String path2) {
        this.path = validateValue("path", path2);
    }

    public String getComment() {
        return this.comment;
    }

    public void setComment(String comment2) {
        this.comment = validateValue("comment", comment2);
    }

    public String getCommentUrl() {
        return this.commentUrl;
    }

    public void setCommentUrl(String commentUrl2) {
        this.commentUrl = validateValue("commentUrl", commentUrl2);
    }

    public boolean isDiscard() {
        return this.discard;
    }

    public void setDiscard(boolean discard2) {
        this.discard = discard2;
    }

    public Set<Integer> getPorts() {
        if (this.unmodifiablePorts == null) {
            this.unmodifiablePorts = Collections.unmodifiableSet(this.ports);
        }
        return this.unmodifiablePorts;
    }

    public void setPorts(int... ports2) {
        int[] arr$;
        if (ports2 == null) {
            throw new NullPointerException("ports");
        }
        int[] portsCopy = (int[]) ports2.clone();
        if (portsCopy.length == 0) {
            Set<Integer> emptySet = Collections.emptySet();
            this.ports = emptySet;
            this.unmodifiablePorts = emptySet;
            return;
        }
        Set<Integer> newPorts = new TreeSet<>();
        for (int p : portsCopy) {
            if (p <= 0 || p > 65535) {
                throw new IllegalArgumentException("port out of range: " + p);
            }
            newPorts.add(Integer.valueOf(p));
        }
        this.ports = newPorts;
        this.unmodifiablePorts = null;
    }

    public void setPorts(Iterable<Integer> ports2) {
        Set<Integer> newPorts = new TreeSet<>();
        for (Integer intValue : ports2) {
            int p = intValue.intValue();
            if (p <= 0 || p > 65535) {
                throw new IllegalArgumentException("port out of range: " + p);
            }
            newPorts.add(Integer.valueOf(p));
        }
        if (newPorts.isEmpty()) {
            Set<Integer> emptySet = Collections.emptySet();
            this.ports = emptySet;
            this.unmodifiablePorts = emptySet;
            return;
        }
        this.ports = newPorts;
        this.unmodifiablePorts = null;
    }

    public int getMaxAge() {
        return this.maxAge;
    }

    public void setMaxAge(int maxAge2) {
        this.maxAge = maxAge2;
    }

    public int getVersion() {
        return this.version;
    }

    public void setVersion(int version2) {
        this.version = version2;
    }

    public boolean isSecure() {
        return this.secure;
    }

    public void setSecure(boolean secure2) {
        this.secure = secure2;
    }

    public boolean isHttpOnly() {
        return this.httpOnly;
    }

    public void setHttpOnly(boolean httpOnly2) {
        this.httpOnly = httpOnly2;
    }

    public int hashCode() {
        return getName().hashCode();
    }

    public boolean equals(Object o) {
        if (!(o instanceof Cookie)) {
            return false;
        }
        Cookie that = (Cookie) o;
        if (!getName().equalsIgnoreCase(that.getName())) {
            return false;
        }
        if (getPath() == null) {
            if (that.getPath() != null) {
                return false;
            }
        } else if (that.getPath() == null || !getPath().equals(that.getPath())) {
            return false;
        }
        if (getDomain() == null) {
            if (that.getDomain() == null) {
                return true;
            }
            return false;
        } else if (that.getDomain() != null) {
            return getDomain().equalsIgnoreCase(that.getDomain());
        } else {
            return false;
        }
    }

    public int compareTo(Cookie c) {
        int v = getName().compareToIgnoreCase(c.getName());
        if (v != 0) {
            return v;
        }
        if (getPath() == null) {
            if (c.getPath() != null) {
                return -1;
            }
        } else if (c.getPath() == null) {
            return 1;
        } else {
            int v2 = getPath().compareTo(c.getPath());
            if (v2 != 0) {
                return v2;
            }
        }
        if (getDomain() == null) {
            if (c.getDomain() == null) {
                return 0;
            }
            return -1;
        } else if (c.getDomain() == null) {
            return 1;
        } else {
            return getDomain().compareToIgnoreCase(c.getDomain());
        }
    }

    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append(getName());
        buf.append('=');
        buf.append(getValue());
        if (getDomain() != null) {
            buf.append(", domain=");
            buf.append(getDomain());
        }
        if (getPath() != null) {
            buf.append(", path=");
            buf.append(getPath());
        }
        if (getComment() != null) {
            buf.append(", comment=");
            buf.append(getComment());
        }
        if (getMaxAge() >= 0) {
            buf.append(", maxAge=");
            buf.append(getMaxAge());
            buf.append('s');
        }
        if (isSecure()) {
            buf.append(", secure");
        }
        if (isHttpOnly()) {
            buf.append(", HTTPOnly");
        }
        return buf.toString();
    }

    private static String validateValue(String name2, String value2) {
        if (value2 == null) {
            return null;
        }
        String value3 = value2.trim();
        if (value3.length() == 0) {
            return null;
        }
        int i = 0;
        while (i < value3.length()) {
            switch (value3.charAt(i)) {
                case 10:
                case 11:
                case 12:
                case 13:
                case ';':
                    throw new IllegalArgumentException(name2 + " contains one of the following prohibited characters: " + ";\\r\\n\\f\\v (" + value3 + ')');
                default:
                    i++;
            }
        }
        return value3;
    }
}