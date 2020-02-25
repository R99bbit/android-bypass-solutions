package retrofit2.mock;

import java.io.IOException;
import okhttp3.Request;
import okhttp3.Request.Builder;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public final class Calls {
    public static <T> Call<T> response(T t) {
        return response(Response.success(t));
    }

    public static <T> Call<T> response(final Response<T> response) {
        return new Call<T>() {
            public void cancel() {
            }

            public Call<T> clone() {
                return this;
            }

            public boolean isCanceled() {
                return false;
            }

            public boolean isExecuted() {
                return false;
            }

            public Response<T> execute() throws IOException {
                return response;
            }

            public void enqueue(Callback<T> callback) {
                callback.onResponse(this, response);
            }

            public Request request() {
                return response.raw().request();
            }
        };
    }

    public static <T> Call<T> failure(final IOException iOException) {
        return new Call<T>() {
            public void cancel() {
            }

            public Call<T> clone() {
                return this;
            }

            public boolean isCanceled() {
                return false;
            }

            public boolean isExecuted() {
                return false;
            }

            public Response<T> execute() throws IOException {
                throw iOException;
            }

            public void enqueue(Callback<T> callback) {
                callback.onFailure(this, iOException);
            }

            public Request request() {
                return new Builder().url((String) "http://localhost").build();
            }
        };
    }

    private Calls() {
        throw new AssertionError("No instances.");
    }
}