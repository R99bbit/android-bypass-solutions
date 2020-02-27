package com.fasterxml.jackson.databind.jsonFormatVisitors;

import java.util.Set;

public interface JsonValueFormatVisitor {

    public static class Base implements JsonValueFormatVisitor {
        public void format(JsonValueFormat jsonValueFormat) {
        }

        public void enumTypes(Set<String> set) {
        }
    }

    void enumTypes(Set<String> set);

    void format(JsonValueFormat jsonValueFormat);
}