package groupproject.backend.util;

import jakarta.servlet.http.HttpServletResponse;

public final class CookieUtil {

    private CookieUtil() {}

    public static void addCookie(HttpServletResponse response,
                                 String name, String value, long maxAgeMs) {
        response.addHeader("Set-Cookie",
                name + "=" + value +
                        "; HttpOnly; Secure; Path=/; SameSite=None; Max-Age=" +
                        (maxAgeMs / 1000));
    }

    public static void clearCookie(HttpServletResponse response, String name) {
        response.addHeader("Set-Cookie",
                name + "=; HttpOnly; Secure; Path=/; SameSite=None; Max-Age=0");
    }
}

