package groupproject.backend.service.impl;

import groupproject.backend.model.Notification;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.NotificationType;
import groupproject.backend.repository.NotificationRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.PagedResponse;
import groupproject.backend.service.NotificationService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class NotificationServiceImpl implements NotificationService {

    private final NotificationRepository notificationRepository;
    private final UserRepository userRepository;

    public NotificationServiceImpl(NotificationRepository notificationRepository,
                                   UserRepository userRepository) {
        this.notificationRepository = notificationRepository;
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    @SuppressWarnings("null")
    public void sendToUser(User user, String title, String message, NotificationType type) {
        Notification notification = Notification.builder()
                .user(user)
                .title(title)
                .message(message)
                .type(type)
                .read(false)
                .build();
        notificationRepository.save(notification);
    }

    @Override
    @Transactional
    public void broadcastToAllActiveUsers(String title, String message) {
        List<User> activeUsers = userRepository.findAll().stream()
                .filter(User::isEnabled)
                .collect(Collectors.toList());
        for (User user : activeUsers) {
            sendToUser(user, title, message, NotificationType.BROADCAST);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<PagedResponse<Map<String, Object>>> getMyNotifications(
            Authentication authentication, int page, int size) {
        User user = getUser(authentication);
        Page<Notification> notifPage = notificationRepository
                .findByUserOrderByReadAscCreatedAtDesc(user, PageRequest.of(page, size));

        List<Map<String, Object>> content = notifPage.getContent().stream()
                .map(this::toMap)
                .collect(Collectors.toList());

        PagedResponse<Map<String, Object>> paged = PagedResponse.<Map<String, Object>>builder()
                .content(content)
                .page(notifPage.getNumber())
                .size(notifPage.getSize())
                .totalElements(notifPage.getTotalElements())
                .totalPages(notifPage.getTotalPages())
                .last(notifPage.isLast())
                .build();

        return ApiResponse.success(paged, "Notifications retrieved");
    }

    @Override
    @Transactional
    @SuppressWarnings("null")
    public ApiResponse<Void> markAsRead(Authentication authentication, UUID notificationId) {
        User user = getUser(authentication);
        Notification notification = notificationRepository.findById(notificationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Notification not found"));
        if (!notification.getUser().getId().equals(user.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not your notification");
        }
        notification.setRead(true);
        notificationRepository.save(notification);
        return ApiResponse.success(null, "Notification marked as read");
    }

    @Override
    @Transactional
    public ApiResponse<Void> markAllAsRead(Authentication authentication) {
        User user = getUser(authentication);
        notificationRepository.markAllReadByUser(user);
        return ApiResponse.success(null, "All notifications marked as read");
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<Map<String, Long>> getUnreadCount(Authentication authentication) {
        User user = getUser(authentication);
        long count = notificationRepository.countByUserAndReadFalse(user);
        Map<String, Long> result = new LinkedHashMap<>();
        result.put("count", count);
        return ApiResponse.success(result, "Unread count retrieved");
    }

    private User getUser(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private Map<String, Object> toMap(Notification n) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", n.getId().toString());
        map.put("title", n.getTitle());
        map.put("message", n.getMessage());
        map.put("type", n.getType().name());
        map.put("isRead", n.isRead());
        map.put("createdAt", n.getCreatedAt().toString());
        return map;
    }
}
