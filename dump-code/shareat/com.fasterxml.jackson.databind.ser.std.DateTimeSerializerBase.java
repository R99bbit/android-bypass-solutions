package com.fasterxml.jackson.databind.ser.std;

import com.fasterxml.jackson.annotation.JsonFormat.Value;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser.NumberType;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonFormatVisitorWrapper;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonIntegerFormatVisitor;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonStringFormatVisitor;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonValueFormat;
import com.fasterxml.jackson.databind.ser.ContextualSerializer;
import com.fasterxml.jackson.databind.util.StdDateFormat;
import java.io.IOException;
import java.lang.reflect.Type;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.TimeZone;

public abstract class DateTimeSerializerBase<T> extends StdScalarSerializer<T> implements ContextualSerializer {
    protected final DateFormat _customFormat;
    protected final boolean _useTimestamp;

    /* access modifiers changed from: protected */
    public abstract long _timestamp(T t);

    public abstract void serialize(T t, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException;

    public abstract DateTimeSerializerBase<T> withFormat(boolean z, DateFormat dateFormat);

    protected DateTimeSerializerBase(Class<T> cls, boolean z, DateFormat dateFormat) {
        super(cls);
        this._useTimestamp = z;
        this._customFormat = dateFormat;
    }

    public JsonSerializer<?> createContextual(SerializerProvider serializerProvider, BeanProperty beanProperty) throws JsonMappingException {
        DateFormat dateFormat;
        TimeZone timeZone;
        if (beanProperty == null) {
            return this;
        }
        Value findFormat = serializerProvider.getAnnotationIntrospector().findFormat(beanProperty.getMember());
        if (findFormat == null) {
            return this;
        }
        if (findFormat.getShape().isNumeric()) {
            return withFormat(true, null);
        }
        TimeZone timeZone2 = findFormat.getTimeZone();
        String pattern = findFormat.getPattern();
        if (pattern.length() > 0) {
            Locale locale = findFormat.getLocale();
            if (locale == null) {
                locale = serializerProvider.getLocale();
            }
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern, locale);
            if (timeZone2 == null) {
                timeZone = serializerProvider.getTimeZone();
            } else {
                timeZone = timeZone2;
            }
            simpleDateFormat.setTimeZone(timeZone);
            return withFormat(false, simpleDateFormat);
        } else if (timeZone2 == null) {
            return this;
        } else {
            DateFormat dateFormat2 = serializerProvider.getConfig().getDateFormat();
            if (dateFormat2.getClass() == StdDateFormat.class) {
                dateFormat = StdDateFormat.getISO8601Format(timeZone2);
            } else {
                dateFormat = (DateFormat) dateFormat2.clone();
                dateFormat.setTimeZone(timeZone2);
            }
            return withFormat(false, dateFormat);
        }
    }

    public boolean isEmpty(T t) {
        return t == null || _timestamp(t) == 0;
    }

    public JsonNode getSchema(SerializerProvider serializerProvider, Type type) {
        boolean z = this._useTimestamp;
        if (!z && this._customFormat == null) {
            z = serializerProvider.isEnabled(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        }
        return createSchemaNode(z ? "number" : "string", true);
    }

    public void acceptJsonFormatVisitor(JsonFormatVisitorWrapper jsonFormatVisitorWrapper, JavaType javaType) throws JsonMappingException {
        boolean z = this._useTimestamp;
        if (!z && this._customFormat == null) {
            z = jsonFormatVisitorWrapper.getProvider().isEnabled(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        }
        if (z) {
            JsonIntegerFormatVisitor expectIntegerFormat = jsonFormatVisitorWrapper.expectIntegerFormat(javaType);
            if (expectIntegerFormat != null) {
                expectIntegerFormat.numberType(NumberType.LONG);
                expectIntegerFormat.format(JsonValueFormat.UTC_MILLISEC);
                return;
            }
            return;
        }
        JsonStringFormatVisitor expectStringFormat = jsonFormatVisitorWrapper.expectStringFormat(javaType);
        if (expectStringFormat != null) {
            expectStringFormat.format(JsonValueFormat.DATE_TIME);
        }
    }
}