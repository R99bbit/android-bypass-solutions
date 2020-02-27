package com.squareup.okhttp;

import com.squareup.okhttp.internal.Util;

public final class Challenge {
    private final String realm;
    private final String scheme;

    public Challenge(String scheme2, String realm2) {
        this.scheme = scheme2;
        this.realm = realm2;
    }

    public String getScheme() {
        return this.scheme;
    }

    public String getRealm() {
        return this.realm;
    }

    public boolean equals(Object o) {
        return (o instanceof Challenge) && Util.equal(this.scheme, ((Challenge) o).scheme) && Util.equal(this.realm, ((Challenge) o).realm);
    }

    public int hashCode() {
        int i;
        int i2 = 0;
        if (this.realm != null) {
            i = this.realm.hashCode();
        } else {
            i = 0;
        }
        int i3 = (i + 899) * 31;
        if (this.scheme != null) {
            i2 = this.scheme.hashCode();
        }
        return i3 + i2;
    }

    public String toString() {
        return this.scheme + " realm=\"" + this.realm + "\"";
    }
}