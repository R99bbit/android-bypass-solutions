package com.igaworks.gson.internal;

import com.igaworks.gson.JsonElement;
import com.igaworks.gson.JsonIOException;
import com.igaworks.gson.JsonNull;
import com.igaworks.gson.JsonParseException;
import com.igaworks.gson.JsonSyntaxException;
import com.igaworks.gson.internal.bind.TypeAdapters;
import com.igaworks.gson.stream.JsonReader;
import com.igaworks.gson.stream.JsonWriter;
import com.igaworks.gson.stream.MalformedJsonException;
import java.io.EOFException;
import java.io.IOException;
import java.io.Writer;

public final class Streams {

    private static final class AppendableWriter extends Writer {
        private final Appendable appendable;
        private final CurrentWrite currentWrite;

        static class CurrentWrite implements CharSequence {
            char[] chars;

            CurrentWrite() {
            }

            public int length() {
                return this.chars.length;
            }

            public char charAt(int i) {
                return this.chars[i];
            }

            public CharSequence subSequence(int start, int end) {
                return new String(this.chars, start, end - start);
            }
        }

        private AppendableWriter(Appendable appendable2) {
            this.currentWrite = new CurrentWrite();
            this.appendable = appendable2;
        }

        /* synthetic */ AppendableWriter(Appendable appendable2, AppendableWriter appendableWriter) {
            this(appendable2);
        }

        public void write(char[] chars, int offset, int length) throws IOException {
            this.currentWrite.chars = chars;
            this.appendable.append(this.currentWrite, offset, offset + length);
        }

        public void write(int i) throws IOException {
            this.appendable.append((char) i);
        }

        public void flush() {
        }

        public void close() {
        }
    }

    public static JsonElement parse(JsonReader reader) throws JsonParseException {
        boolean isEmpty = true;
        try {
            reader.peek();
            isEmpty = false;
            return (JsonElement) TypeAdapters.JSON_ELEMENT.read(reader);
        } catch (EOFException e) {
            if (isEmpty) {
                return JsonNull.INSTANCE;
            }
            throw new JsonSyntaxException((Throwable) e);
        } catch (MalformedJsonException e2) {
            throw new JsonSyntaxException((Throwable) e2);
        } catch (IOException e3) {
            throw new JsonIOException((Throwable) e3);
        } catch (NumberFormatException e4) {
            throw new JsonSyntaxException((Throwable) e4);
        }
    }

    public static void write(JsonElement element, JsonWriter writer) throws IOException {
        TypeAdapters.JSON_ELEMENT.write(writer, element);
    }

    public static Writer writerForAppendable(Appendable appendable) {
        return appendable instanceof Writer ? (Writer) appendable : new AppendableWriter(appendable, null);
    }
}