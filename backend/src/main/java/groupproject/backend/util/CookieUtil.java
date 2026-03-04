package groupproject.backend.util;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Cookie utility that conditionally sets the Secure flag based on the active profile.
 * In production the Secure flag is required (HTTPS). In dev (HTTP) it must be omitted
 * or the browser will silently reject the cookie.
 */
@Component
public class CookieUtil {

    private final boolean secureCookies;

    public CookieUtil(
            @Value("${spring.profiles.active:dev}") String activeProfile) {
        // Enable Secure flag only when running in production profile
        this.secureCookies = activeProfile.contains("prod");
    }

    public void addCookie(HttpServletResponse response,
                          String name, String value, long maxAgeMs) {
        String cookie = name + "=" + value +
                "; HttpOnly; Path=/; SameSite=" + (secureCookies ? "None" : "Lax") +
                (secureCookies ? "; Secure" : "") +
                "; Max-Age=" + (maxAgeMs / 1000);
        response.addHeader("Set-Cookie", cookie);
    }

    public void clearCookie(HttpServletResponse response, String name) {
        String cookie = name + "=; HttpOnly; Path=/; SameSite=" +
                (secureCookies ? "None" : "Lax") +
                (secureCookies ? "; Secure" : "") +
                "; Max-Age=0";
        response.addHeader("Set-Cookie", cookie);
    }
}


