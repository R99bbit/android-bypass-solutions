package com.fasterxml.jackson.databind;

import com.fasterxml.jackson.core.FormatSchema;
import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

public class MappingIterator<T> implements Iterator<T>, Closeable {
    protected static final MappingIterator<?> EMPTY_ITERATOR = new MappingIterator<>(null, null, null, null, false, null);
    protected final boolean _closeParser;
    protected final DeserializationContext _context;
    protected final JsonDeserializer<T> _deserializer;
    protected boolean _hasNextChecked;
    protected JsonParser _parser;
    protected final JavaType _type;
    protected final T _updatedValue;

    @Deprecated
    protected MappingIterator(JavaType javaType, JsonParser jsonParser, DeserializationContext deserializationContext, JsonDeserializer<?> jsonDeserializer) {
        this(javaType, jsonParser, deserializationContext, jsonDeserializer, true, null);
    }

    protected MappingIterator(JavaType javaType, JsonParser jsonParser, DeserializationContext deserializationContext, JsonDeserializer<?> jsonDeserializer, boolean z, Object obj) {
        this._type = javaType;
        this._parser = jsonParser;
        this._context = deserializationContext;
        this._deserializer = jsonDeserializer;
        this._closeParser = z;
        if (obj == null) {
            this._updatedValue = null;
        } else {
            this._updatedValue = obj;
        }
        if (z && jsonParser != null && jsonParser.getCurrentToken() == JsonToken.START_ARRAY) {
            jsonParser.clearCurrentToken();
        }
    }

    protected static <T> MappingIterator<T> emptyIterator() {
        return EMPTY_ITERATOR;
    }

    public boolean hasNext() {
        try {
            return hasNextValue();
        } catch (JsonMappingException e) {
            throw new RuntimeJsonMappingException(e.getMessage(), e);
        } catch (IOException e2) {
            throw new RuntimeException(e2.getMessage(), e2);
        }
    }

    public T next() {
        try {
            return nextValue();
        } catch (JsonMappingException e) {
            throw new RuntimeJsonMappingException(e.getMessage(), e);
        } catch (IOException e2) {
            throw new RuntimeException(e2.getMessage(), e2);
        }
    }

    public void remove() {
        throw new UnsupportedOperationException();
    }

    public void close() throws IOException {
        if (this._parser != null) {
            this._parser.close();
        }
    }

    public boolean hasNextValue() throws IOException {
        if (this._parser == null) {
            return false;
        }
        if (!this._hasNextChecked) {
            JsonToken currentToken = this._parser.getCurrentToken();
            this._hasNextChecked = true;
            if (currentToken == null) {
                JsonToken nextToken = this._parser.nextToken();
                if (nextToken == null || nextToken == JsonToken.END_ARRAY) {
                    JsonParser jsonParser = this._parser;
                    this._parser = null;
                    if (!this._closeParser) {
                        return false;
                    }
                    jsonParser.close();
                    return false;
                }
            }
        }
        return true;
    }

    public T nextValue() throws IOException {
        T t;
        if (!this._hasNextChecked && !hasNextValue()) {
            throw new NoSuchElementException();
        } else if (this._parser == null) {
            throw new NoSuchElementException();
        } else {
            this._hasNextChecked = false;
            if (this._updatedValue == null) {
                t = this._deserializer.deserialize(this._parser, this._context);
            } else {
                this._deserializer.deserialize(this._parser, this._context, this._updatedValue);
                t = this._updatedValue;
            }
            this._parser.clearCurrentToken();
            return t;
        }
    }

    public List<T> readAll() throws IOException {
        return readAll(new ArrayList());
    }

    public List<T> readAll(List<T> list) throws IOException {
        while (hasNextValue()) {
            list.add(nextValue());
        }
        return list;
    }

    public JsonParser getParser() {
        return this._parser;
    }

    public FormatSchema getParserSchema() {
        return this._parser.getSchema();
    }

    public JsonLocation getCurrentLocation() {
        return this._parser.getCurrentLocation();
    }
}