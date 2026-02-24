package groupproject.backend.service;

import groupproject.backend.model.User;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.function.Function;

public interface JwtService {
    String generateAccessToken(User user);
    String extractUserName(String token);
    <T> T extractClaim(String token, Function<Claims, T> claimsResolver);
    boolean validateToken(String token, UserDetails userDetails) ;
    String getRefreshToken(User user);
    boolean validateRefreshToken(String refreshToken);

}
