package com.fasterxml.jackson.databind.deser;

import com.fasterxml.jackson.annotation.ObjectIdGenerator;
import com.fasterxml.jackson.annotation.ObjectIdGenerator.IdKey;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonDeserializer.None;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.KeyDeserializer;
import com.fasterxml.jackson.databind.annotation.NoClass;
import com.fasterxml.jackson.databind.cfg.HandlerInstantiator;
import com.fasterxml.jackson.databind.deser.impl.ReadableObjectId;
import com.fasterxml.jackson.databind.introspect.Annotated;
import com.fasterxml.jackson.databind.util.ClassUtil;
import java.io.Serializable;
import java.util.LinkedHashMap;

public abstract class DefaultDeserializationContext extends DeserializationContext implements Serializable {
    private static final long serialVersionUID = 1;
    protected transient LinkedHashMap<IdKey, ReadableObjectId> _objectIds;

    public static final class Impl extends DefaultDeserializationContext {
        private static final long serialVersionUID = 1;

        public Impl(DeserializerFactory deserializerFactory) {
            super(deserializerFactory, (DeserializerCache) null);
        }

        protected Impl(Impl impl, DeserializationConfig deserializationConfig, JsonParser jsonParser, InjectableValues injectableValues) {
            super(impl, deserializationConfig, jsonParser, injectableValues);
        }

        protected Impl(Impl impl, DeserializerFactory deserializerFactory) {
            super((DefaultDeserializationContext) impl, deserializerFactory);
        }

        public DefaultDeserializationContext createInstance(DeserializationConfig deserializationConfig, JsonParser jsonParser, InjectableValues injectableValues) {
            return new Impl(this, deserializationConfig, jsonParser, injectableValues);
        }

        public DefaultDeserializationContext with(DeserializerFactory deserializerFactory) {
            return new Impl(this, deserializerFactory);
        }
    }

    public abstract DefaultDeserializationContext createInstance(DeserializationConfig deserializationConfig, JsonParser jsonParser, InjectableValues injectableValues);

    public abstract DefaultDeserializationContext with(DeserializerFactory deserializerFactory);

    protected DefaultDeserializationContext(DeserializerFactory deserializerFactory, DeserializerCache deserializerCache) {
        super(deserializerFactory, deserializerCache);
    }

    protected DefaultDeserializationContext(DefaultDeserializationContext defaultDeserializationContext, DeserializationConfig deserializationConfig, JsonParser jsonParser, InjectableValues injectableValues) {
        super(defaultDeserializationContext, deserializationConfig, jsonParser, injectableValues);
    }

    protected DefaultDeserializationContext(DefaultDeserializationContext defaultDeserializationContext, DeserializerFactory deserializerFactory) {
        super((DeserializationContext) defaultDeserializationContext, deserializerFactory);
    }

    public ReadableObjectId findObjectId(Object obj, ObjectIdGenerator<?> objectIdGenerator) {
        IdKey key = objectIdGenerator.key(obj);
        if (this._objectIds == null) {
            this._objectIds = new LinkedHashMap<>();
        } else {
            ReadableObjectId readableObjectId = this._objectIds.get(key);
            if (readableObjectId != null) {
                return readableObjectId;
            }
        }
        ReadableObjectId readableObjectId2 = new ReadableObjectId(obj);
        this._objectIds.put(key, readableObjectId2);
        return readableObjectId2;
    }

    public JsonDeserializer<Object> deserializerInstance(Annotated annotated, Object obj) throws JsonMappingException {
        JsonDeserializer<?> jsonDeserializer = null;
        if (obj != null) {
            if (obj instanceof JsonDeserializer) {
                jsonDeserializer = (JsonDeserializer) obj;
            } else if (!(obj instanceof Class)) {
                throw new IllegalStateException("AnnotationIntrospector returned deserializer definition of type " + obj.getClass().getName() + "; expected type JsonDeserializer or Class<JsonDeserializer> instead");
            } else {
                Class<NoClass> cls = (Class) obj;
                if (!(cls == None.class || cls == NoClass.class)) {
                    if (!JsonDeserializer.class.isAssignableFrom(cls)) {
                        throw new IllegalStateException("AnnotationIntrospector returned Class " + cls.getName() + "; expected Class<JsonDeserializer>");
                    }
                    HandlerInstantiator handlerInstantiator = this._config.getHandlerInstantiator();
                    if (handlerInstantiator != null) {
                        jsonDeserializer = handlerInstantiator.deserializerInstance(this._config, annotated, cls);
                    }
                    if (jsonDeserializer == null) {
                        jsonDeserializer = (JsonDeserializer) ClassUtil.createInstance(cls, this._config.canOverrideAccessModifiers());
                    }
                }
            }
            if (jsonDeserializer instanceof ResolvableDeserializer) {
                ((ResolvableDeserializer) jsonDeserializer).resolve(this);
            }
        }
        return jsonDeserializer;
    }

    public final KeyDeserializer keyDeserializerInstance(Annotated annotated, Object obj) throws JsonMappingException {
        KeyDeserializer keyDeserializer = null;
        if (obj != null) {
            if (obj instanceof KeyDeserializer) {
                keyDeserializer = (KeyDeserializer) obj;
            } else if (!(obj instanceof Class)) {
                throw new IllegalStateException("AnnotationIntrospector returned key deserializer definition of type " + obj.getClass().getName() + "; expected type KeyDeserializer or Class<KeyDeserializer> instead");
            } else {
                Class<NoClass> cls = (Class) obj;
                if (!(cls == KeyDeserializer.None.class || cls == NoClass.class)) {
                    if (!KeyDeserializer.class.isAssignableFrom(cls)) {
                        throw new IllegalStateException("AnnotationIntrospector returned Class " + cls.getName() + "; expected Class<KeyDeserializer>");
                    }
                    HandlerInstantiator handlerInstantiator = this._config.getHandlerInstantiator();
                    if (handlerInstantiator != null) {
                        keyDeserializer = handlerInstantiator.keyDeserializerInstance(this._config, annotated, cls);
                    }
                    if (keyDeserializer == null) {
                        keyDeserializer = (KeyDeserializer) ClassUtil.createInstance(cls, this._config.canOverrideAccessModifiers());
                    }
                }
            }
            if (keyDeserializer instanceof ResolvableDeserializer) {
                ((ResolvableDeserializer) keyDeserializer).resolve(this);
            }
        }
        return keyDeserializer;
    }
}