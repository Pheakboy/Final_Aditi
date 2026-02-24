package groupproject.backend.service.impl;

import groupproject.backend.model.RefreshToken;
import groupproject.backend.repository.RefreshTokenRepository;
import groupproject.backend.service.RefreshTokenService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenServiceImpl(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public RefreshToken verify(String token) {

        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (refreshToken.isRevoked()) {
            throw new RuntimeException("Refresh token revoked");
        }

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        return refreshToken;
    }

    @Override
    @Transactional
    public void revoke(String token) {
        refreshTokenRepository.findByToken(token)
                .ifPresent(rt -> {
                    rt.setRevoked(true);
                    refreshTokenRepository.save(rt);
                });
    }
}