package groupproject.backend.service;

import groupproject.backend.model.RefreshToken;

public interface RefreshTokenService {
    RefreshToken verify (String token);
    void revoke(String token);
}