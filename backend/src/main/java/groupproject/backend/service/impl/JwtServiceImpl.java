package groupproject.backend.service.impl;

import groupproject.backend.config.JwtProperties;
import groupproject.backend.model.RefreshToken;
import groupproject.backend.model.Role;
import groupproject.backend.model.User;
import groupproject.backend.repository.RefreshTokenRepository;
import groupproject.backend.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private final JwtProperties jwtProperties;
    private final RefreshTokenRepository refreshTokenRepository;

    private SecretKey getSigninKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    @Override
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("uid", user.getId());
        List<String> roles = user.getRoles()
                .stream()
                .map(Role::getName)   // assuming getName() returns "USER"
                .toList();
        claims.put("roles", roles);
        return Jwts.builder()
                .setSubject(user.getUsername())
                .addClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getExpiration()))
                .signWith(getSigninKey())
                .compact();
    }


    @Override
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }


    @Override
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    @Override
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    @Override
    public String getRefreshToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()
                        + jwtProperties.getRefreshExpiration()))
                .signWith(getSigninKey())
                .compact();
    }

    @Override
    public boolean validateRefreshToken(String refreshToken) {
        try {
            // 1️⃣ Verify signature + structure
            String username = extractUserName(refreshToken);

            // 2️⃣ Check expiration
            if (isTokenExpired(refreshToken)) {
                return false;
            }

            // 3️⃣ Check token exists in DB
            RefreshToken storedToken = refreshTokenRepository
                    .findByToken(refreshToken)
                    .orElse(null);

            if (storedToken == null) {
                return false;
            }

            // 4️⃣ Check not revoked
            if (storedToken.isRevoked()) {
                return false;
            }

            // 5️⃣ Check username matches
            return storedToken.getUser().getEmail().equals(username);

        } catch (Exception e) {
            return false;
        }
    }

}