package com.igaworks.gson;

import java.lang.reflect.Type;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

final class DefaultDateTypeAdapter implements JsonSerializer<Date>, JsonDeserializer<Date> {
    private final DateFormat enUsFormat;
    private final DateFormat iso8601Format;
    private final DateFormat localFormat;

    DefaultDateTypeAdapter() {
        this(DateFormat.getDateTimeInstance(2, 2, Locale.US), DateFormat.getDateTimeInstance(2, 2));
    }

    DefaultDateTypeAdapter(String datePattern) {
        this((DateFormat) new SimpleDateFormat(datePattern, Locale.US), (DateFormat) new SimpleDateFormat(datePattern));
    }

    DefaultDateTypeAdapter(int style) {
        this(DateFormat.getDateInstance(style, Locale.US), DateFormat.getDateInstance(style));
    }

    public DefaultDateTypeAdapter(int dateStyle, int timeStyle) {
        this(DateFormat.getDateTimeInstance(dateStyle, timeStyle, Locale.US), DateFormat.getDateTimeInstance(dateStyle, timeStyle));
    }

    DefaultDateTypeAdapter(DateFormat enUsFormat2, DateFormat localFormat2) {
        this.enUsFormat = enUsFormat2;
        this.localFormat = localFormat2;
        this.iso8601Format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        this.iso8601Format.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    public JsonElement serialize(Date src, Type typeOfSrc, JsonSerializationContext context) {
        JsonPrimitive jsonPrimitive;
        synchronized (this.localFormat) {
            jsonPrimitive = new JsonPrimitive(this.enUsFormat.format(src));
        }
        return jsonPrimitive;
    }

    public Date deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        if (!(json instanceof JsonPrimitive)) {
            throw new JsonParseException((String) "The date should be a string value");
        }
        Date date = deserializeToDate(json);
        if (typeOfT == Date.class) {
            return date;
        }
        if (typeOfT == Timestamp.class) {
            return new Timestamp(date.getTime());
        }
        if (typeOfT == java.sql.Date.class) {
            return new java.sql.Date(date.getTime());
        }
        throw new IllegalArgumentException(getClass() + " cannot deserialize to " + typeOfT);
    }

    private Date deserializeToDate(JsonElement json) {
        Date parse;
        synchronized (this.localFormat) {
            try {
                parse = this.localFormat.parse(json.getAsString());
            } catch (ParseException e) {
                throw new JsonSyntaxException(json.getAsString(), e);
            } catch (ParseException e2) {
                try {
                    parse = this.enUsFormat.parse(json.getAsString());
                } catch (ParseException e3) {
                    parse = this.iso8601Format.parse(json.getAsString());
                }
            }
        }
        return parse;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(DefaultDateTypeAdapter.class.getSimpleName());
        sb.append('(').append(this.localFormat.getClass().getSimpleName()).append(')');
        return sb.toString();
    }
}