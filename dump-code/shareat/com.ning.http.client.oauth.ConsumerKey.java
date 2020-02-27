package com.ning.http.client.oauth;

public class ConsumerKey {
    private final String key;
    private final String secret;

    public ConsumerKey(String key2, String secret2) {
        this.key = key2;
        this.secret = secret2;
    }

    public String getKey() {
        return this.key;
    }

    public String getSecret() {
        return this.secret;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("{Consumer key, key=");
        appendValue(sb, this.key);
        sb.append(", secret=");
        appendValue(sb, this.secret);
        sb.append("}");
        return sb.toString();
    }

    private void appendValue(StringBuilder sb, String value) {
        if (value == null) {
            sb.append("null");
            return;
        }
        sb.append('\"');
        sb.append(value);
        sb.append('\"');
    }

    public int hashCode() {
        return this.key.hashCode() + this.secret.hashCode();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        ConsumerKey other = (ConsumerKey) o;
        if (!this.key.equals(other.key) || !this.secret.equals(other.secret)) {
            return false;
        }
        return true;
    }
}