package groupproject.backend.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.nio.charset.StandardCharsets;

import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import groupproject.backend.dto.AnalyticsDTO;
import groupproject.backend.dto.LoanDecisionRequestDTO;
import groupproject.backend.dto.LoanResponseDTO;
import groupproject.backend.dto.TransactionResponseDTO;
import groupproject.backend.dto.UserProfileDTO;
import groupproject.backend.model.AuditLog;
import groupproject.backend.model.Loan;
import groupproject.backend.model.LoanDecision;
import groupproject.backend.model.Role;
import groupproject.backend.model.Transaction;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.LoanStatus;
import groupproject.backend.model.enums.NotificationType;
import groupproject.backend.model.enums.RiskLevel;
import groupproject.backend.model.enums.TransactionType;
import groupproject.backend.repository.AuditLogRepository;
import groupproject.backend.repository.LoanDecisionRepository;
import groupproject.backend.repository.LoanRepository;
import groupproject.backend.repository.RoleRepository;
import groupproject.backend.repository.TransactionRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.PagedResponse;
import groupproject.backend.service.AuditLogService;
import groupproject.backend.service.LoanService;
import groupproject.backend.service.NotificationService;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    // ─── Dependencies ─────────────────────────────────────────────────────────

    private final LoanService loanService;
    private final LoanRepository loanRepository;
    private final LoanDecisionRepository loanDecisionRepository;
    private final UserRepository userRepository;
    private final TransactionRepository transactionRepository;
    private final AuditLogService auditLogService;
    private final AuditLogRepository auditLogRepository;
    private final NotificationService notificationService;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public AdminController(LoanService loanService,
                           LoanRepository loanRepository,
                           LoanDecisionRepository loanDecisionRepository,
                           UserRepository userRepository,
                           TransactionRepository transactionRepository,
                           AuditLogService auditLogService,
                           AuditLogRepository auditLogRepository,
                           NotificationService notificationService,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder) {
        this.loanService = loanService;
        this.loanRepository = loanRepository;
        this.loanDecisionRepository = loanDecisionRepository;
        this.userRepository = userRepository;
        this.transactionRepository = transactionRepository;
        this.auditLogService = auditLogService;
        this.auditLogRepository = auditLogRepository;
        this.notificationService = notificationService;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ─── Loan List Endpoints ──────────────────────────────────────────────────

    @GetMapping("/loans")
    public ResponseEntity<ApiResponse<List<LoanResponseDTO>>> getAllLoans() {
        return ResponseEntity.ok(loanService.getAllLoans());
    }

    @GetMapping("/loans/pending")
    public ResponseEntity<ApiResponse<List<LoanResponseDTO>>> getPendingLoans() {
        return ResponseEntity.ok(loanService.getPendingLoans());
    }

    @GetMapping("/loans/paged")
    public ResponseEntity<ApiResponse<PagedResponse<LoanResponseDTO>>> getLoansFiltered(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String riskLevel,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to) {
        return ResponseEntity.ok(loanService.getLoansFiltered(page, size, status, riskLevel, from, to));
    }

    // ─── Loan Detail ──────────────────────────────────────────────────────────

    @GetMapping("/loans/{loanId}")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<LoanResponseDTO>> getLoanById(@PathVariable UUID loanId) {
        Loan loan = loanRepository.findById(loanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Loan not found"));
        return ResponseEntity.ok(ApiResponse.success(mapLoanToDTO(loan), "Loan retrieved"));
    }

    // ─── Loan Decision ────────────────────────────────────────────────────────

    @PostMapping("/loans/{loanId}/decide")
    public ResponseEntity<ApiResponse<LoanResponseDTO>> decideLoan(
            Authentication authentication,
            @PathVariable UUID loanId,
            @Valid @RequestBody LoanDecisionRequestDTO request) {
        ApiResponse<LoanResponseDTO> result = loanService.decideLoan(authentication, loanId, request);
        // Send notification to loan applicant
        Loan loan = loanRepository.findById(loanId).orElse(null);
        if (loan != null) {
            boolean approved = "APPROVED".equalsIgnoreCase(request.getDecision());
            String title = approved ? "Loan Approved" : "Loan Rejected";
            String message = approved
                    ? "Your loan application of " + loan.getLoanAmount() + " has been approved."
                    : "Your loan application of " + loan.getLoanAmount() + " has been rejected." +
                      (request.getNote() != null ? " Reason: " + request.getNote() : "");
            notificationService.sendToUser(loan.getUser(), title, message,
                    approved ? NotificationType.LOAN_APPROVED : NotificationType.LOAN_REJECTED);
        }
        return ResponseEntity.ok(result);
    }

    // ─── Bulk Loan Actions ────────────────────────────────────────────────────

    @Data
    public static class BulkLoanRequest {
        @NotNull private List<String> loanIds;
        private String note;
    }

    @PostMapping("/loans/bulk-approve")
    @Transactional
    public ResponseEntity<ApiResponse<Map<String, Object>>> bulkApproveLoan(
            Authentication authentication,
            @Valid @RequestBody BulkLoanRequest request) {
        int count = 0;
        List<String> skipped = new ArrayList<>();
        for (String idStr : request.getLoanIds()) {
            try {
                UUID loanId = UUID.fromString(idStr);
                Loan loan = loanRepository.findById(loanId).orElse(null);
                if (loan == null || loan.getStatus() != LoanStatus.PENDING) {
                    skipped.add(idStr);
                    continue;
                }
                loan.setStatus(LoanStatus.APPROVED);
                loan.setAdminNote(request.getNote());
                loanRepository.save(loan);
                LoanDecision decision = LoanDecision.builder()
                        .loan(loan).admin(getAdminUser(authentication))
                        .decision(LoanStatus.APPROVED).note(request.getNote()).build();
                loanDecisionRepository.save(decision);
                notificationService.sendToUser(loan.getUser(), "Loan Approved",
                        "Your loan of " + loan.getLoanAmount() + " has been approved.", NotificationType.LOAN_APPROVED);
                count++;
            } catch (Exception e) { skipped.add(idStr); }
        }
        auditLogService.log("BULK_LOAN_APPROVED", authentication.getName(),
                "Bulk approved " + count + " loans. Skipped: " + skipped, null, "LOAN", null);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("approved", count);
        result.put("skipped", skipped);
        return ResponseEntity.ok(ApiResponse.success(result, count + " loans approved"));
    }

    @PostMapping("/loans/bulk-reject")
    @Transactional
    public ResponseEntity<ApiResponse<Map<String, Object>>> bulkRejectLoan(
            Authentication authentication,
            @Valid @RequestBody BulkLoanRequest request) {
        int count = 0;
        List<String> skipped = new ArrayList<>();
        for (String idStr : request.getLoanIds()) {
            try {
                UUID loanId = UUID.fromString(idStr);
                Loan loan = loanRepository.findById(loanId).orElse(null);
                if (loan == null || loan.getStatus() != LoanStatus.PENDING) {
                    skipped.add(idStr);
                    continue;
                }
                loan.setStatus(LoanStatus.REJECTED);
                loan.setAdminNote(request.getNote());
                loanRepository.save(loan);
                LoanDecision decision = LoanDecision.builder()
                        .loan(loan).admin(getAdminUser(authentication))
                        .decision(LoanStatus.REJECTED).note(request.getNote()).build();
                loanDecisionRepository.save(decision);
                notificationService.sendToUser(loan.getUser(), "Loan Rejected",
                        "Your loan of " + loan.getLoanAmount() + " was rejected." +
                        (request.getNote() != null ? " Reason: " + request.getNote() : ""),
                        NotificationType.LOAN_REJECTED);
                count++;
            } catch (Exception e) { skipped.add(idStr); }
        }
        auditLogService.log("BULK_LOAN_REJECTED", authentication.getName(),
                "Bulk rejected " + count + " loans. Skipped: " + skipped, null, "LOAN", null);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rejected", count);
        result.put("skipped", skipped);
        return ResponseEntity.ok(ApiResponse.success(result, count + " loans rejected"));
    }

    // ─── Loan Export ──────────────────────────────────────────────────────────

    @GetMapping("/loans/export")
    @Transactional(readOnly = true)
    public ResponseEntity<byte[]> exportLoans(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String riskLevel) {
        List<Loan> loans = loanRepository.findAllByOrderByCreatedAtDesc();
        // Apply optional filters
        if (status != null && !status.isBlank()) {
            try {
                LoanStatus s = LoanStatus.valueOf(status.toUpperCase());
                loans = loans.stream().filter(l -> l.getStatus() == s).collect(Collectors.toList());
            } catch (IllegalArgumentException ignored) {}
        }
        if (riskLevel != null && !riskLevel.isBlank()) {
            try {
                RiskLevel rl = RiskLevel.valueOf(riskLevel.toUpperCase());
                loans = loans.stream().filter(l -> l.getRiskLevel() == rl).collect(Collectors.toList());
            } catch (IllegalArgumentException ignored) {}
        }
        StringBuilder sb = new StringBuilder("ID,User Name,Email,Amount,Purpose,Risk Score,Risk Level,Status,Applied Date,Decision Date,Admin Note\n");
        for (Loan l : loans) {
            // Find latest decision date
            String decisionDate = loanDecisionRepository.findByLoanOrderByDecidedAtDesc(l)
                    .stream().findFirst()
                    .map(d -> d.getDecidedAt() != null ? d.getDecidedAt().toLocalDate().toString() : "")
                    .orElse("");
            sb.append(l.getId()).append(",")
              .append(csvEscape(l.getUser().getRealUsername())).append(",")
              .append(csvEscape(l.getUser().getEmail())).append(",")
              .append(l.getLoanAmount()).append(",")
              .append(csvEscape(l.getPurpose() != null ? l.getPurpose() : "")).append(",")
              .append(l.getRiskScore() != null ? l.getRiskScore() : "").append(",")
              .append(l.getRiskLevel() != null ? l.getRiskLevel().name() : "").append(",")
              .append(l.getStatus().name()).append(",")
              .append(l.getCreatedAt() != null ? l.getCreatedAt().toLocalDate() : "").append(",")
              .append(decisionDate).append(",")
              .append(csvEscape(l.getAdminNote() != null ? l.getAdminNote() : "")).append("\n");
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"loans.csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    // ─── User List ────────────────────────────────────────────────────────────

    @GetMapping("/users")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllUsers(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) Boolean enabled) {
        List<User> users = userRepository.findAll();
        if (enabled != null) users = users.stream().filter(u -> u.isEnabled() == enabled).collect(Collectors.toList());
        if (search != null && !search.isBlank()) {
            String q = search.toLowerCase();
            users = users.stream().filter(u -> u.getRealUsername().toLowerCase().contains(q)
                    || u.getEmail().toLowerCase().contains(q)).collect(Collectors.toList());
        }
        List<Map<String, Object>> result = users.stream().map(this::mapUserToMap).collect(Collectors.toList());
        return ResponseEntity.ok(ApiResponse.success(result, "Users retrieved"));
    }

    // ─── User Detail ──────────────────────────────────────────────────────────

    @GetMapping("/users/{userId}")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<UserProfileDTO>> getUserProfile(@PathVariable Long userId) {
        User user = getUserById(userId);
        BigDecimal totalIncome = transactionRepository.sumAmountByUserAndType(user, TransactionType.INCOME);
        BigDecimal totalExpenses = transactionRepository.sumAmountByUserAndType(user, TransactionType.EXPENSE);
        if (totalIncome == null) totalIncome = BigDecimal.ZERO;
        if (totalExpenses == null) totalExpenses = BigDecimal.ZERO;
        BigDecimal savings = totalIncome.subtract(totalExpenses);
        long txCount = transactionRepository.countByUser(user);
        List<Loan> loans = loanRepository.findByUserOrderByCreatedAtDesc(user);
        Double latestRiskScore = loans.isEmpty() ? null : loans.get(0).getRiskScore();
        String latestRiskLevel = (loans.isEmpty() || loans.get(0).getRiskLevel() == null)
                ? null : loans.get(0).getRiskLevel().name();
        List<LoanResponseDTO> loanDTOs = loans.stream().map(this::mapLoanToDTO).collect(Collectors.toList());
        List<Transaction> recentTx = transactionRepository.findByUserOrderByCreatedAtDesc(user)
                .stream().limit(10).collect(Collectors.toList());
        List<TransactionResponseDTO> txDTOs = recentTx.stream().map(this::mapTxToDTO).collect(Collectors.toList());
        UserProfileDTO profile = UserProfileDTO.builder()
                .id(user.getId()).username(user.getRealUsername()).email(user.getEmail())
                .phoneNumber(user.getPhoneNumber()).address(user.getAddress()).bio(user.getBio())
                .enabled(user.isEnabled())
                .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                .totalIncome(totalIncome).totalExpenses(totalExpenses).savingsBalance(savings)
                .totalTransactions(txCount).latestRiskScore(latestRiskScore).latestRiskLevel(latestRiskLevel)
                .loans(loanDTOs).recentTransactions(txDTOs).build();
        return ResponseEntity.ok(ApiResponse.success(profile, "User profile retrieved"));
    }

    // ─── User CRUD ────────────────────────────────────────────────────────────

    @Data
    public static class CreateUserRequest {
        @NotBlank private String username;
        @NotBlank private String email;
        private String role = "USER";
        private String phoneNumber;
        private String address;
    }

    @Data
    public static class UpdateUserRequest {
        private String username;
        private String email;
        private String phoneNumber;
        private String address;
        private String bio;
    }

    @PostMapping("/users")
    @Transactional
    public ResponseEntity<ApiResponse<Map<String, Object>>> createUser(
            Authentication authentication,
            @Valid @RequestBody CreateUserRequest req) {
        if (userRepository.findByEmail(req.getEmail()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already in use");
        }
        String tempPassword = "TempPass@" + System.currentTimeMillis() % 10000;
        User user = new User();
        user.setUsername(req.getUsername());
        user.setEmail(req.getEmail());
        user.setPassword(passwordEncoder.encode(tempPassword));
        user.setEnabled(true);
        user.setPhoneNumber(req.getPhoneNumber());
        user.setAddress(req.getAddress());
        String roleName = "ADMIN".equalsIgnoreCase(req.getRole()) ? "ADMIN" : "USER";
        Set<Role> roles = new java.util.HashSet<>();
        roleRepository.findByName(roleName).ifPresent(roles::add);
        user.setRoles(roles);
        User saved = userRepository.save(user);
        auditLogService.log("ADMIN_CREATED_USER", authentication.getName(),
                "Created user " + saved.getEmail(), saved.getId().toString(), "USER", null);
        Map<String, Object> result = mapUserToMap(saved);
        result.put("temporaryPassword", tempPassword);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(result, "User created"));
    }

    @PutMapping("/users/{userId}")
    @Transactional
    public ResponseEntity<ApiResponse<Map<String, Object>>> updateUser(
            Authentication authentication,
            @PathVariable Long userId,
            @RequestBody UpdateUserRequest req) {
        User user = getUserById(userId);
        if (req.getUsername() != null && !req.getUsername().isBlank()) user.setUsername(req.getUsername());
        if (req.getEmail() != null && !req.getEmail().isBlank()) user.setEmail(req.getEmail());
        if (req.getPhoneNumber() != null) user.setPhoneNumber(req.getPhoneNumber());
        if (req.getAddress() != null) user.setAddress(req.getAddress());
        if (req.getBio() != null) user.setBio(req.getBio());
        User saved = userRepository.save(user);
        auditLogService.log("ADMIN_UPDATED_USER", authentication.getName(),
                "Updated user " + saved.getEmail(), userId.toString(), "USER", null);
        return ResponseEntity.ok(ApiResponse.success(mapUserToMap(saved), "User updated"));
    }

    @PutMapping("/users/{userId}/deactivate")
    @Transactional
    public ResponseEntity<ApiResponse<Void>> deactivateUser(
            Authentication authentication, @PathVariable Long userId) {
        User user = getUserById(userId);
        user.setEnabled(false);
        userRepository.save(user);
        auditLogService.log("ADMIN_DEACTIVATED_USER", authentication.getName(),
                "Deactivated user " + user.getEmail(), userId.toString(), "USER", null);
        return ResponseEntity.ok(ApiResponse.success(null, "User deactivated"));
    }

    @PutMapping("/users/{userId}/reactivate")
    @Transactional
    public ResponseEntity<ApiResponse<Void>> reactivateUser(
            Authentication authentication, @PathVariable Long userId) {
        User user = getUserById(userId);
        user.setEnabled(true);
        userRepository.save(user);
        auditLogService.log("ADMIN_REACTIVATED_USER", authentication.getName(),
                "Reactivated user " + user.getEmail(), userId.toString(), "USER", null);
        return ResponseEntity.ok(ApiResponse.success(null, "User reactivated"));
    }

    // ─── User Loans / Transactions (for Admin) ────────────────────────────────

    @GetMapping("/users/{userId}/loans")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<List<LoanResponseDTO>>> getUserLoans(@PathVariable Long userId) {
        User user = getUserById(userId);
        List<LoanResponseDTO> loans = loanRepository.findByUserOrderByCreatedAtDesc(user)
                .stream().map(this::mapLoanToDTO).collect(Collectors.toList());
        return ResponseEntity.ok(ApiResponse.success(loans, "User loans retrieved"));
    }

    @GetMapping("/users/{userId}/transactions")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<List<TransactionResponseDTO>>> getUserTransactions(
            @PathVariable Long userId,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to) {
        User user = getUserById(userId);
        List<Transaction> all = transactionRepository.findByUserOrderByCreatedAtDesc(user);
        List<TransactionResponseDTO> filtered = all.stream()
                .filter(t -> {
                    if (type != null && !type.isBlank()) {
                        try { if (!t.getType().equals(TransactionType.valueOf(type.toUpperCase()))) return false; }
                        catch (IllegalArgumentException e) { return false; }
                    }
                    if (from != null && t.getTransactionDate() != null && t.getTransactionDate().isBefore(from)) return false;
                    if (to   != null && t.getTransactionDate() != null && t.getTransactionDate().isAfter(to)) return false;
                    return true;
                })
                .map(this::mapTxToDTO).collect(Collectors.toList());
        return ResponseEntity.ok(ApiResponse.success(filtered, "User transactions retrieved"));
    }

    // ─── User Export ──────────────────────────────────────────────────────────

    @GetMapping("/users/export")
    @Transactional(readOnly = true)
    public ResponseEntity<byte[]> exportUsers(Authentication authentication) {
        List<User> users = userRepository.findAll();
        StringBuilder sb = new StringBuilder("ID,Name,Email,Roles,Status,Total Loans\n");
        for (User u : users) {
            long totalLoans = loanRepository.countByUser(u);
            String roles = u.getRoles().stream().map(Role::getName).collect(Collectors.joining("|"));
            sb.append(u.getId()).append(",")
              .append(csvEscape(u.getRealUsername())).append(",")
              .append(csvEscape(u.getEmail())).append(",")
              .append(csvEscape(roles)).append(",")
              .append(u.isEnabled() ? "Active" : "Disabled").append(",")
              .append(totalLoans).append("\n");
        }
        auditLogService.log("DATA_EXPORTED", authentication.getName(), "Exported user list", null, "USER", null);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"users.csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    // ─── Analytics ────────────────────────────────────────────────────────────

    @GetMapping("/analytics")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<AnalyticsDTO>> getAnalytics() {
        long lowCount = loanRepository.countByRiskLevel(RiskLevel.LOW);
        long mediumCount = loanRepository.countByRiskLevel(RiskLevel.MEDIUM);
        long highCount = loanRepository.countByRiskLevel(RiskLevel.HIGH);
        long totalLoans = loanRepository.count();
        AnalyticsDTO.RiskDistribution riskDistribution = AnalyticsDTO.RiskDistribution.builder()
                .low(lowCount).medium(mediumCount).high(highCount).total(totalLoans).build();
        long approved = loanRepository.countByStatus(LoanStatus.APPROVED);
        long rejected = loanRepository.countByStatus(LoanStatus.REJECTED);
        long pending = loanRepository.countByStatus(LoanStatus.PENDING);
        long decided = approved + rejected;
        AnalyticsDTO.ApprovalRate approvalRate = AnalyticsDTO.ApprovalRate.builder()
                .approved(approved).rejected(rejected).pending(pending).total(totalLoans)
                .approvalPercentage(decided > 0 ? (approved * 100.0 / decided) : 0)
                .rejectionPercentage(decided > 0 ? (rejected * 100.0 / decided) : 0).build();
        List<Object[]> monthlyCounts = loanRepository.findMonthlyLoanCounts();
        List<AnalyticsDTO.MonthlyStats> monthlyStats = new ArrayList<>();
        for (Object[] row : monthlyCounts) {
            monthlyStats.add(AnalyticsDTO.MonthlyStats.builder()
                    .year(((Number) row[1]).intValue()).month(((Number) row[0]).intValue())
                    .count(((Number) row[2]).longValue()).build());
        }
        List<Object[]> highRiskRows = loanRepository.findTopHighRiskUsers(RiskLevel.HIGH);
        List<AnalyticsDTO.HighRiskUser> topHighRiskUsers = new ArrayList<>();
        int limit = 0;
        for (Object[] row : highRiskRows) {
            if (limit++ >= 10) break;
            User u = (User) row[0];
            double score = row[1] != null ? ((Number) row[1]).doubleValue() : 0;
            topHighRiskUsers.add(AnalyticsDTO.HighRiskUser.builder()
                    .email(u.getEmail()).username(u.getRealUsername()).riskScore(score).build());
        }
        AnalyticsDTO analytics = AnalyticsDTO.builder()
                .riskDistribution(riskDistribution).approvalRate(approvalRate)
                .monthlyStats(monthlyStats).topHighRiskUsers(topHighRiskUsers).build();
        return ResponseEntity.ok(ApiResponse.success(analytics, "Analytics retrieved"));
    }

    @GetMapping("/analytics/summary")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAnalyticsSummary() {
        long totalUsers = userRepository.count();
        long totalLoans = loanRepository.count();
        long pendingLoans = loanRepository.countByStatus(LoanStatus.PENDING);
        long approvedLoans = loanRepository.countByStatus(LoanStatus.APPROVED);
        long rejectedLoans = loanRepository.countByStatus(LoanStatus.REJECTED);
        long decided = approvedLoans + rejectedLoans;
        double approvalRate = decided > 0 ? (approvedLoans * 100.0 / decided) : 0;
        // Average risk score of all loans
        double avgRisk = loanRepository.findAll().stream()
                .filter(l -> l.getRiskScore() != null)
                .mapToDouble(l -> l.getRiskScore()).average().orElse(0);
        // Total approved loan amount
        BigDecimal totalApprovedAmount = loanRepository.findByStatusOrderByCreatedAtDesc(LoanStatus.APPROVED).stream()
                .map(Loan::getLoanAmount).filter(java.util.Objects::nonNull)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
        // New users this month
        long newUsersThisMonth = userRepository.count(); // simplified monthly

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("totalUsers", totalUsers);
        result.put("totalLoans", totalLoans);
        result.put("pendingLoans", pendingLoans);
        result.put("approvedLoans", approvedLoans);
        result.put("rejectedLoans", rejectedLoans);
        result.put("approvalRate", Math.round(approvalRate * 10.0) / 10.0);
        result.put("averageRiskScore", Math.round(avgRisk * 10.0) / 10.0);
        result.put("totalApprovedAmount", totalApprovedAmount);
        return ResponseEntity.ok(ApiResponse.success(result, "Analytics summary retrieved"));
    }

    @GetMapping("/analytics/user-growth")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getUserGrowth() {
        // Return simple list grouped by month — using all users for now
        List<User> all = userRepository.findAll();
        Map<String, Long> grouped = all.stream().collect(
            Collectors.groupingBy(u -> "N/A", Collectors.counting()));
        List<Map<String, Object>> result = grouped.entrySet().stream().map(e -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("month", e.getKey());
            m.put("count", e.getValue());
            return m;
        }).collect(Collectors.toList());
        return ResponseEntity.ok(ApiResponse.success(result, "User growth retrieved"));
    }

    @GetMapping("/analytics/export")
    @Transactional(readOnly = true)
    public ResponseEntity<byte[]> exportAnalytics(Authentication authentication) {
        long approved = loanRepository.countByStatus(LoanStatus.APPROVED);
        long rejected = loanRepository.countByStatus(LoanStatus.REJECTED);
        long pending  = loanRepository.countByStatus(LoanStatus.PENDING);
        long total    = loanRepository.count();
        long low   = loanRepository.countByRiskLevel(RiskLevel.LOW);
        long medium = loanRepository.countByRiskLevel(RiskLevel.MEDIUM);
        long high  = loanRepository.countByRiskLevel(RiskLevel.HIGH);
        StringBuilder sb = new StringBuilder("Metric,Value\n");
        sb.append("Total Loans,").append(total).append("\n");
        sb.append("Approved Loans,").append(approved).append("\n");
        sb.append("Rejected Loans,").append(rejected).append("\n");
        sb.append("Pending Loans,").append(pending).append("\n");
        sb.append("Approval Rate %,").append(total > 0 ? String.format("%.1f", approved * 100.0 / total) : "0").append("\n");
        sb.append("Low Risk Loans,").append(low).append("\n");
        sb.append("Medium Risk Loans,").append(medium).append("\n");
        sb.append("High Risk Loans,").append(high).append("\n");
        auditLogService.log("DATA_EXPORTED", authentication.getName(), "Exported analytics report", null, "ANALYTICS", null);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"analytics.csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    // ─── Audit Logs ───────────────────────────────────────────────────────────

    @GetMapping("/audit-logs")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<PagedResponse<AuditLog>>> getAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to) {

        Specification<AuditLog> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (action != null && !action.isBlank())
                predicates.add(cb.like(cb.upper(root.get("action")), "%" + action.toUpperCase() + "%"));
            if (from != null)
                predicates.add(cb.greaterThanOrEqualTo(root.get("timestamp"), from.atStartOfDay()));
            if (to != null)
                predicates.add(cb.lessThanOrEqualTo(root.get("timestamp"), to.atTime(23, 59, 59)));
            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<AuditLog> logPage = auditLogRepository.findAll(spec,
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "timestamp")));

        PagedResponse<AuditLog> paged = PagedResponse.<AuditLog>builder()
                .content(logPage.getContent()).page(logPage.getNumber()).size(logPage.getSize())
                .totalElements(logPage.getTotalElements()).totalPages(logPage.getTotalPages())
                .last(logPage.isLast()).build();

        return ResponseEntity.ok(ApiResponse.success(paged, "Audit logs retrieved"));
    }

    // ─── Notifications ────────────────────────────────────────────────────────

    @Data
    public static class NotificationRequest {
        @NotBlank private String title;
        @NotBlank private String message;
    }

    @PostMapping("/notifications/broadcast")
    @Transactional
    public ResponseEntity<ApiResponse<Void>> broadcastNotification(
            Authentication authentication,
            @Valid @RequestBody NotificationRequest req) {
        notificationService.broadcastToAllActiveUsers(req.getTitle(), req.getMessage());
        auditLogService.log("BROADCAST_SENT", authentication.getName(),
                "Broadcast: " + req.getTitle(), null, null, null);
        return ResponseEntity.ok(ApiResponse.success(null, "Broadcast sent to all active users"));
    }

    @PostMapping("/notifications/user/{userId}")
    @Transactional
    public ResponseEntity<ApiResponse<Void>> sendNotificationToUser(
            Authentication authentication,
            @PathVariable Long userId,
            @Valid @RequestBody NotificationRequest req) {
        User user = getUserById(userId);
        notificationService.sendToUser(user, req.getTitle(), req.getMessage(), NotificationType.GENERAL);
        auditLogService.log("NOTIFICATION_SENT", authentication.getName(),
                "Sent to user " + user.getEmail() + ": " + req.getTitle(), userId.toString(), "USER", null);
        return ResponseEntity.ok(ApiResponse.success(null, "Notification sent to user"));
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private User getAdminUser(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Admin not found"));
    }

    private Map<String, Object> mapUserToMap(User u) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", u.getId());
        map.put("username", u.getRealUsername());
        map.put("email", u.getEmail());
        map.put("roles", u.getRoles().stream().map(r -> "ROLE_" + r.getName()).collect(Collectors.toSet()));
        map.put("phoneNumber", u.getPhoneNumber());
        map.put("address", u.getAddress());
        map.put("enabled", u.isEnabled());
        return map;
    }

    private LoanResponseDTO mapLoanToDTO(Loan loan) {
        return LoanResponseDTO.builder()
                .id(loan.getId()).loanAmount(loan.getLoanAmount())
                .monthlyIncome(loan.getMonthlyIncome()).monthlyExpense(loan.getMonthlyExpense())
                .riskScore(loan.getRiskScore()).riskLevel(loan.getRiskLevel())
                .status(loan.getStatus()).purpose(loan.getPurpose()).adminNote(loan.getAdminNote())
                .createdAt(loan.getCreatedAt()).updatedAt(loan.getUpdatedAt())
                .applicantEmail(loan.getUser().getEmail())
                .applicantUsername(loan.getUser().getRealUsername()).build();
    }

    private TransactionResponseDTO mapTxToDTO(Transaction t) {
        return TransactionResponseDTO.builder()
                .id(t.getId()).type(t.getType()).amount(t.getAmount())
                .description(t.getDescription()).transactionDate(t.getTransactionDate())
                .createdAt(t.getCreatedAt()).build();
    }

    private String csvEscape(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n"))
            return "\"" + value.replace("\"", "\"\"") + "\"";
        return value;
    }
}
