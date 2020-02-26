package retrofit2;

import com.kakao.network.ServerProtocol;

public class HttpException extends RuntimeException {
    private final int code;
    private final String message;
    private final transient Response<?> response;

    private static String getMessage(Response<?> response2) {
        Utils.checkNotNull(response2, "response == null");
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP ");
        sb.append(response2.code());
        sb.append(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
        sb.append(response2.message());
        return sb.toString();
    }

    public HttpException(Response<?> response2) {
        super(getMessage(response2));
        this.code = response2.code();
        this.message = response2.message();
        this.response = response2;
    }

    public int code() {
        return this.code;
    }

    public String message() {
        return this.message;
    }

    public Response<?> response() {
        return this.response;
    }
}