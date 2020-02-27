package org.jboss.netty.util;

public interface ThreadNameDeterminer {
    public static final ThreadNameDeterminer CURRENT = new ThreadNameDeterminer() {
        public String determineThreadName(String currentThreadName, String proposedThreadName) throws Exception {
            return null;
        }
    };
    public static final ThreadNameDeterminer PROPOSED = new ThreadNameDeterminer() {
        public String determineThreadName(String currentThreadName, String proposedThreadName) throws Exception {
            return proposedThreadName;
        }
    };

    String determineThreadName(String str, String str2) throws Exception;
}