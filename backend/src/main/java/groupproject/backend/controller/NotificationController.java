package groupproject.backend.controller;

import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.PagedResponse;
import groupproject.backend.service.NotificationService;
import jakarta.validation.constraints.Min;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

/**
 * Provides direct /api/notifications/** endpoints for the frontend.
 * (The existing /api/users/me/notifications routes in UserController still work too.)
 */
@RestController
@RequestMapping("/api/notifications")
public class NotificationController {

    private final NotificationService notificationService;

    public NotificationController(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    @GetMapping("/history")
    public ResponseEntity<ApiResponse<PagedResponse<Map<String, Object>>>> getHistory(
            Authentication authentication,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) int size) {
        return ResponseEntity.ok(notificationService.getMyNotifications(authentication, page, size));
    }

    @PutMapping("/{id}/read")
    public ResponseEntity<ApiResponse<Void>> markRead(
            Authentication authentication,
            @PathVariable UUID id) {
        return ResponseEntity.ok(notificationService.markAsRead(authentication, id));
    }

    @PutMapping("/read-all")
    public ResponseEntity<ApiResponse<Void>> markAllRead(Authentication authentication) {
        return ResponseEntity.ok(notificationService.markAllAsRead(authentication));
    }

    @GetMapping("/unread-count")
    public ResponseEntity<ApiResponse<Map<String, Long>>> getUnreadCount(Authentication authentication) {
        return ResponseEntity.ok(notificationService.getUnreadCount(authentication));
    }
}
