package groupproject.backend.service;

import groupproject.backend.request.AuthLoginRequest;
import groupproject.backend.request.RegisterRequest;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.AuthResponse;
import groupproject.backend.response.MeResponse;
import groupproject.backend.response.RegisterResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

public interface AuthService {
    AuthResponse login(AuthLoginRequest request, HttpServletResponse response);
    ApiResponse<RegisterResponse> register(RegisterRequest request);
    void logout(String refreshToken, HttpServletResponse response);
    MeResponse me(Authentication authentication);
    ResponseEntity<?> refresh(String refreshToken, HttpServletResponse response);
}
