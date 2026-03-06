package groupproject.backend.controller;

import groupproject.backend.dto.LoanResponseDTO;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.PagedResponse;
import groupproject.backend.service.LoanService;
import groupproject.backend.service.NotificationService;
import groupproject.backend.service.TransactionService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.Map;
import java.util.UUID;

/**
 * Handles all /api/users/me/* endpoints:
 * - Notifications (get, mark read, mark all read, unread count)
 * - Transaction export CSV
 */
@RestController
@RequestMapping("/api/users/me")
public class UserController {

    private final NotificationService notificationService;
    private final TransactionService transactionService;
    private final LoanService loanService;

    public UserController(NotificationService notificationService,
                          TransactionService transactionService,
                          LoanService loanService) {
        this.notificationService = notificationService;
        this.transactionService = transactionService;
        this.loanService = loanService;
    }

    // ─── Notifications ──────────────────────────────────────────────────────

    @GetMapping("/notifications")
    public ResponseEntity<ApiResponse<PagedResponse<Map<String, Object>>>> getMyNotifications(
            Authentication authentication,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(notificationService.getMyNotifications(authentication, page, size));
    }

    @PutMapping("/notifications/{id}/read")
    public ResponseEntity<ApiResponse<Void>> markAsRead(
            Authentication authentication,
            @PathVariable UUID id) {
        return ResponseEntity.ok(notificationService.markAsRead(authentication, id));
    }

    @PutMapping("/notifications/read-all")
    public ResponseEntity<ApiResponse<Void>> markAllAsRead(Authentication authentication) {
        return ResponseEntity.ok(notificationService.markAllAsRead(authentication));
    }

    @GetMapping("/notifications/unread-count")
    public ResponseEntity<ApiResponse<Map<String, Long>>> getUnreadCount(Authentication authentication) {
        return ResponseEntity.ok(notificationService.getUnreadCount(authentication));
    }

    // ─── My Loans ────────────────────────────────────────────────────────────

    @GetMapping("/loans/{loanId}")
    public ResponseEntity<ApiResponse<LoanResponseDTO>> getMyLoanById(
            Authentication authentication,
            @PathVariable UUID loanId) {
        return ResponseEntity.ok(loanService.getLoanByIdForUser(authentication, loanId));
    }

    // ─── Transaction Export ──────────────────────────────────────────────────

    @GetMapping("/transactions/export")
    public ResponseEntity<byte[]> exportTransactions(
            Authentication authentication,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to) {
        byte[] csv = transactionService.exportTransactionsCsv(authentication, type, from, to);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"transactions.csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }
}
