package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Currency;
import java.util.HashSet;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

public class JdkDeserializers {
    private static final HashSet<String> _classNames = new HashSet<>();

    public static class CurrencyDeserializer extends FromStringDeserializer<Currency> {
        public static final CurrencyDeserializer instance = new CurrencyDeserializer();

        public CurrencyDeserializer() {
            super(Currency.class);
        }

        /* access modifiers changed from: protected */
        public Currency _deserialize(String str, DeserializationContext deserializationContext) throws IllegalArgumentException {
            return Currency.getInstance(str);
        }
    }

    public static class FileDeserializer extends FromStringDeserializer<File> {
        public static final FileDeserializer instance = new FileDeserializer();

        public FileDeserializer() {
            super(File.class);
        }

        /* access modifiers changed from: protected */
        public File _deserialize(String str, DeserializationContext deserializationContext) {
            return new File(str);
        }
    }

    protected static class LocaleDeserializer extends FromStringDeserializer<Locale> {
        public static final LocaleDeserializer instance = new LocaleDeserializer();

        public LocaleDeserializer() {
            super(Locale.class);
        }

        /* access modifiers changed from: protected */
        public Locale _deserialize(String str, DeserializationContext deserializationContext) throws IOException {
            int indexOf = str.indexOf(95);
            if (indexOf < 0) {
                return new Locale(str);
            }
            String substring = str.substring(0, indexOf);
            String substring2 = str.substring(indexOf + 1);
            int indexOf2 = substring2.indexOf(95);
            if (indexOf2 < 0) {
                return new Locale(substring, substring2);
            }
            return new Locale(substring, substring2.substring(0, indexOf2), substring2.substring(indexOf2 + 1));
        }
    }

    public static class PatternDeserializer extends FromStringDeserializer<Pattern> {
        public static final PatternDeserializer instance = new PatternDeserializer();

        public PatternDeserializer() {
            super(Pattern.class);
        }

        /* access modifiers changed from: protected */
        public Pattern _deserialize(String str, DeserializationContext deserializationContext) throws IllegalArgumentException {
            return Pattern.compile(str);
        }
    }

    public static class URIDeserializer extends FromStringDeserializer<URI> {
        public static final URIDeserializer instance = new URIDeserializer();

        public URIDeserializer() {
            super(URI.class);
        }

        /* access modifiers changed from: protected */
        public URI _deserialize(String str, DeserializationContext deserializationContext) throws IllegalArgumentException {
            return URI.create(str);
        }
    }

    public static class URLDeserializer extends FromStringDeserializer<URL> {
        public static final URLDeserializer instance = new URLDeserializer();

        public URLDeserializer() {
            super(URL.class);
        }

        /* access modifiers changed from: protected */
        public URL _deserialize(String str, DeserializationContext deserializationContext) throws IOException {
            return new URL(str);
        }
    }

    static {
        for (Class name : new Class[]{UUID.class, URL.class, URI.class, File.class, Currency.class, Pattern.class, Locale.class, InetAddress.class, InetSocketAddress.class, Charset.class, AtomicBoolean.class, Class.class, StackTraceElement.class, ByteBuffer.class}) {
            _classNames.add(name.getName());
        }
    }

    public static JsonDeserializer<?> find(Class<?> cls, String str) {
        if (!_classNames.contains(str)) {
            return null;
        }
        if (cls == URI.class) {
            return URIDeserializer.instance;
        }
        if (cls == URL.class) {
            return URLDeserializer.instance;
        }
        if (cls == File.class) {
            return FileDeserializer.instance;
        }
        if (cls == UUID.class) {
            return UUIDDeserializer.instance;
        }
        if (cls == Currency.class) {
            return CurrencyDeserializer.instance;
        }
        if (cls == Pattern.class) {
            return PatternDeserializer.instance;
        }
        if (cls == Locale.class) {
            return LocaleDeserializer.instance;
        }
        if (cls == InetAddress.class) {
            return InetAddressDeserializer.instance;
        }
        if (cls == InetSocketAddress.class) {
            return InetSocketAddressDeserializer.instance;
        }
        if (cls == Charset.class) {
            return new CharsetDeserializer();
        }
        if (cls == Class.class) {
            return ClassDeserializer.instance;
        }
        if (cls == StackTraceElement.class) {
            return StackTraceElementDeserializer.instance;
        }
        if (cls == AtomicBoolean.class) {
            return AtomicBooleanDeserializer.instance;
        }
        if (cls == ByteBuffer.class) {
            return new ByteBufferDeserializer();
        }
        throw new IllegalArgumentException("Internal error: can't find deserializer for " + str);
    }
}