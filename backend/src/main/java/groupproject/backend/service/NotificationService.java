package groupproject.backend.service;

import groupproject.backend.model.User;
import groupproject.backend.model.enums.NotificationType;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.PagedResponse;
import org.springframework.security.core.Authentication;

import java.util.Map;
import java.util.UUID;

public interface NotificationService {
    void sendToUser(User user, String title, String message, NotificationType type);
    void broadcastToAllActiveUsers(String title, String message);
    ApiResponse<PagedResponse<Map<String, Object>>> getMyNotifications(Authentication authentication, int page, int size);
    ApiResponse<Void> markAsRead(Authentication authentication, UUID notificationId);
    ApiResponse<Void> markAllAsRead(Authentication authentication);
    ApiResponse<Map<String, Long>> getUnreadCount(Authentication authentication);
}
