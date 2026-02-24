package groupproject.backend.service.impl;

import groupproject.backend.config.JwtProperties;
import groupproject.backend.model.RefreshToken;
import groupproject.backend.model.Role;
import groupproject.backend.model.User;
import groupproject.backend.repository.RefreshTokenRepository;
import groupproject.backend.repository.RoleRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.request.AuthLoginRequest;
import groupproject.backend.request.RegisterRequest;
import groupproject.backend.request.UpdateProfileRequest;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.AuthResponse;
import groupproject.backend.response.MeResponse;
import groupproject.backend.response.RegisterResponse;
import groupproject.backend.service.AuthService;
import groupproject.backend.service.JwtService;
import groupproject.backend.service.RefreshTokenService;
import groupproject.backend.util.CookieUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProperties jwtProperties;

    public AuthServiceImpl(AuthenticationManager authenticationManager,
                           UserRepository userRepository,
                           RoleRepository roleRepository,
                           JwtService jwtService,
                           RefreshTokenService refreshTokenService,
                           RefreshTokenRepository refreshTokenRepository,
                           PasswordEncoder passwordEncoder,
                           JwtProperties jwtProperties) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProperties = jwtProperties;
    }

    @Override
    @Transactional
    public ApiResponse<RegisterResponse> register(RegisterRequest request) {

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already registered");
        }

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match");
        }

        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Default role USER not found"));

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnable(true);
        user.setRoles(Set.of(userRole));

        userRepository.save(user);

        RegisterResponse data = RegisterResponse.builder()
                .id(user.getId())
                .username(user.getRealUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                .build();

        return ApiResponse.success(data, "Registration successful");
    }

    @Override
    @Transactional
    public AuthResponse login(AuthLoginRequest request,
                              HttpServletResponse response) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // Remove all old refresh tokens for this user before issuing a new one
        refreshTokenRepository.deleteAllByUser(user);

        RefreshToken tokenEntity = new RefreshToken();
        tokenEntity.setToken(refreshToken);
        tokenEntity.setUser(user);
        tokenEntity.setRevoked(false);
        tokenEntity.setExpiresAt(Instant.now().plusMillis(jwtProperties.getRefreshExpiration()));

        refreshTokenRepository.save(tokenEntity);

        CookieUtil.addCookie(response, "accessToken", accessToken, jwtProperties.getExpiration());
        CookieUtil.addCookie(response, "refreshToken", refreshToken, jwtProperties.getRefreshExpiration());

        return AuthResponse.builder()
                .type("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .roles(user.getRoles()
                        .stream()
                        .map(Role::getName)
                        .collect(Collectors.toSet()))
                .build();
    }


    @Override
    public MeResponse me(Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Not authenticated");
        }

        String email = authentication.getName();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        MeResponse res = new MeResponse();
        res.setEmail(user.getEmail());
        res.setUsername(user.getRealUsername());
        res.setPhoto(user.getPhoto());
        res.setPhoneNumber(user.getPhoneNumber());
        res.setAddress(user.getAddress());
        res.setBio(user.getBio());
        res.setRoles(
                user.getRoles()
                        .stream()
                        .map(Role::getName)
                        .collect(Collectors.toSet()));

        return res;
    }


    @Override
    @Transactional
    public void logout(String refreshToken, HttpServletResponse response) {

        if (refreshToken != null) {
            refreshTokenService.revoke(refreshToken);
        }

        CookieUtil.clearCookie(response, "accessToken");
        CookieUtil.clearCookie(response, "refreshToken");
    }


    @Override
    @Transactional
    public ApiResponse<Void> refresh(String refreshToken, HttpServletResponse response) {

        if (refreshToken == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token missing");
        }

        // Validates: exists in DB, not revoked, and expiresAt has not passed
        RefreshToken storedToken = refreshTokenService.verify(refreshToken);

        // Also validate JWT signature / structure
        if (!jwtService.validateRefreshToken(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }

        User user = storedToken.getUser();

        String newAccessToken = jwtService.generateAccessToken(user);
        CookieUtil.addCookie(response, "accessToken", newAccessToken, jwtProperties.getExpiration());

        return ApiResponse.success(null, "Token refreshed");
    }

    @Override
    @Transactional
    public ApiResponse<MeResponse> updateProfile(Authentication authentication, UpdateProfileRequest request) {

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Not authenticated");
        }

        String email = authentication.getName();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        // Only update fields that are provided (not null)
        if (request.getUsername() != null) {
            user.setUsername(request.getUsername());
        }
        if (request.getPhoneNumber() != null) {
            user.setPhoneNumber(request.getPhoneNumber());
        }
        if (request.getAddress() != null) {
            user.setAddress(request.getAddress());
        }
        if (request.getBio() != null) {
            user.setBio(request.getBio());
        }
        if (request.getPhoto() != null) {
            user.setPhoto(request.getPhoto());
        }

        userRepository.save(user);

        MeResponse data = new MeResponse();
        data.setEmail(user.getEmail());
        data.setUsername(user.getRealUsername());
        data.setPhoto(user.getPhoto());
        data.setPhoneNumber(user.getPhoneNumber());
        data.setAddress(user.getAddress());
        data.setBio(user.getBio());
        data.setRoles(
                user.getRoles()
                        .stream()
                        .map(Role::getName)
                        .collect(Collectors.toSet()));

        return ApiResponse.success(data, "Profile updated successfully");
    }

}