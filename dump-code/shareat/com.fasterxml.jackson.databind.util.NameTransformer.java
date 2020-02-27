package com.fasterxml.jackson.databind.util;

public abstract class NameTransformer {
    public static final NameTransformer NOP = new NameTransformer() {
        public String transform(String str) {
            return str;
        }

        public String reverse(String str) {
            return str;
        }
    };

    public static class Chained extends NameTransformer {
        protected final NameTransformer _t1;
        protected final NameTransformer _t2;

        public Chained(NameTransformer nameTransformer, NameTransformer nameTransformer2) {
            this._t1 = nameTransformer;
            this._t2 = nameTransformer2;
        }

        public String transform(String str) {
            return this._t1.transform(this._t2.transform(str));
        }

        public String reverse(String str) {
            String reverse = this._t1.reverse(str);
            if (reverse != null) {
                return this._t2.reverse(reverse);
            }
            return reverse;
        }

        public String toString() {
            return "[ChainedTransformer(" + this._t1 + ", " + this._t2 + ")]";
        }
    }

    public abstract String reverse(String str);

    public abstract String transform(String str);

    protected NameTransformer() {
    }

    public static NameTransformer simpleTransformer(final String str, final String str2) {
        boolean z = true;
        boolean z2 = str != null && str.length() > 0;
        if (str2 == null || str2.length() <= 0) {
            z = false;
        }
        if (!z2) {
            return z ? new NameTransformer() {
                public String transform(String str) {
                    return str + str2;
                }

                public String reverse(String str) {
                    if (str.endsWith(str2)) {
                        return str.substring(0, str.length() - str2.length());
                    }
                    return null;
                }

                public String toString() {
                    return "[SuffixTransformer('" + str2 + "')]";
                }
            } : NOP;
        }
        if (z) {
            return new NameTransformer() {
                public String transform(String str) {
                    return str + str + str2;
                }

                public String reverse(String str) {
                    if (str.startsWith(str)) {
                        String substring = str.substring(str.length());
                        if (substring.endsWith(str2)) {
                            return substring.substring(0, substring.length() - str2.length());
                        }
                    }
                    return null;
                }

                public String toString() {
                    return "[PreAndSuffixTransformer('" + str + "','" + str2 + "')]";
                }
            };
        }
        return new NameTransformer() {
            public String transform(String str) {
                return str + str;
            }

            public String reverse(String str) {
                if (str.startsWith(str)) {
                    return str.substring(str.length());
                }
                return null;
            }

            public String toString() {
                return "[PrefixTransformer('" + str + "')]";
            }
        };
    }

    public static NameTransformer chainedTransformer(NameTransformer nameTransformer, NameTransformer nameTransformer2) {
        return new Chained(nameTransformer, nameTransformer2);
    }
}