package co.habitfactory.signalfinance_embrain.retroapi;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import okhttp3.MediaType;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.Converter;
import retrofit2.Converter.Factory;
import retrofit2.Retrofit;

class ToStringConverterFactory extends Factory {
    /* access modifiers changed from: private */
    public static final MediaType MEDIA_TYPE = MediaType.parse("text/plain");

    ToStringConverterFactory() {
    }

    public Converter<ResponseBody, ?> responseBodyConverter(Type type, Annotation[] annotationArr, Retrofit retrofit) {
        if (String.class.equals(type)) {
            return new Converter<ResponseBody, String>() {
                public String convert(ResponseBody responseBody) throws IOException {
                    return responseBody.string();
                }
            };
        }
        return null;
    }

    public Converter<?, RequestBody> requestBodyConverter(Type type, Annotation[] annotationArr, Annotation[] annotationArr2, Retrofit retrofit) {
        if (String.class.equals(type)) {
            return new Converter<String, RequestBody>() {
                public RequestBody convert(String str) throws IOException {
                    return RequestBody.create(ToStringConverterFactory.MEDIA_TYPE, str);
                }
            };
        }
        return null;
    }
}