package groupproject.backend.controller;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import groupproject.backend.dto.AnalyticsDTO;
import groupproject.backend.dto.LoanDecisionRequestDTO;
import groupproject.backend.dto.LoanResponseDTO;
import groupproject.backend.dto.TransactionResponseDTO;
import groupproject.backend.dto.UserProfileDTO;
import groupproject.backend.model.AuditLog;
import groupproject.backend.model.Loan;
import groupproject.backend.model.Role;
import groupproject.backend.model.Transaction;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.LoanStatus;
import groupproject.backend.model.enums.RiskLevel;
import groupproject.backend.model.enums.TransactionType;
import groupproject.backend.repository.AuditLogRepository;
import groupproject.backend.repository.LoanRepository;
import groupproject.backend.repository.TransactionRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.PagedResponse;
import groupproject.backend.service.AuditLogService;
import groupproject.backend.service.LoanService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final LoanService loanService;
    private final LoanRepository loanRepository;
    private final UserRepository userRepository;
    private final TransactionRepository transactionRepository;
    private final AuditLogService auditLogService;
    private final AuditLogRepository auditLogRepository;

    public AdminController(LoanService loanService,
                           LoanRepository loanRepository,
                           UserRepository userRepository,
                           TransactionRepository transactionRepository,
                           AuditLogService auditLogService,
                           AuditLogRepository auditLogRepository) {
        this.loanService = loanService;
        this.loanRepository = loanRepository;
        this.userRepository = userRepository;
        this.transactionRepository = transactionRepository;
        this.auditLogService = auditLogService;
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping("/loans")
    public ResponseEntity<ApiResponse<List<LoanResponseDTO>>> getAllLoans() {
        return ResponseEntity.ok(loanService.getAllLoans());
    }

    @GetMapping("/loans/pending")
    public ResponseEntity<ApiResponse<List<LoanResponseDTO>>> getPendingLoans() {
        return ResponseEntity.ok(loanService.getPendingLoans());
    }

    /**
     * Paginated + filtered loan list.
     * All query params are optional.
     * Example: GET /api/admin/loans/paged?page=0&size=10&status=PENDING&riskLevel=HIGH&from=2025-01-01&to=2025-12-31
     */
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

    @PostMapping("/loans/{loanId}/decide")
    public ResponseEntity<ApiResponse<LoanResponseDTO>> decideLoan(
            Authentication authentication,
            @PathVariable UUID loanId,
            @Valid @RequestBody LoanDecisionRequestDTO request) {
        return ResponseEntity.ok(loanService.decideLoan(authentication, loanId, request));
    }

    // â”€â”€ Analytics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @GetMapping("/analytics")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<AnalyticsDTO>> getAnalytics() {
        // Risk distribution
        long lowCount = loanRepository.countByRiskLevel(RiskLevel.LOW);
        long mediumCount = loanRepository.countByRiskLevel(RiskLevel.MEDIUM);
        long highCount = loanRepository.countByRiskLevel(RiskLevel.HIGH);
        long totalLoans = loanRepository.count();

        AnalyticsDTO.RiskDistribution riskDistribution = AnalyticsDTO.RiskDistribution.builder()
                .low(lowCount)
                .medium(mediumCount)
                .high(highCount)
                .total(totalLoans)
                .build();

        // Approval rate
        long approved = loanRepository.countByStatus(LoanStatus.APPROVED);
        long rejected = loanRepository.countByStatus(LoanStatus.REJECTED);
        long pending = loanRepository.countByStatus(LoanStatus.PENDING);
        long decided = approved + rejected;

        AnalyticsDTO.ApprovalRate approvalRate = AnalyticsDTO.ApprovalRate.builder()
                .approved(approved)
                .rejected(rejected)
                .pending(pending)
                .total(totalLoans)
                .approvalPercentage(decided > 0 ? (approved * 100.0 / decided) : 0)
                .rejectionPercentage(decided > 0 ? (rejected * 100.0 / decided) : 0)
                .build();

        // Monthly stats
        List<Object[]> monthlyCounts = loanRepository.findMonthlyLoanCounts();
        List<AnalyticsDTO.MonthlyStats> monthlyStats = new java.util.ArrayList<>();
        for (Object[] row : monthlyCounts) {
            monthlyStats.add(AnalyticsDTO.MonthlyStats.builder()
                    .year(((Number) row[1]).intValue())
                    .month(((Number) row[0]).intValue())
                    .count(((Number) row[2]).longValue())
                    .build());
        }

        // Top high risk users (up to 10)
        List<Object[]> highRiskRows = loanRepository.findTopHighRiskUsers(RiskLevel.HIGH);
        List<AnalyticsDTO.HighRiskUser> topHighRiskUsers = new java.util.ArrayList<>();
        int limit = 0;
        for (Object[] row : highRiskRows) {
            if (limit++ >= 10) break;
            User u = (User) row[0];
            double score = row[1] != null ? ((Number) row[1]).doubleValue() : 0;
            topHighRiskUsers.add(AnalyticsDTO.HighRiskUser.builder()
                    .email(u.getEmail())
                    .username(u.getRealUsername())
                    .riskScore(score)
                    .build());
        }

        AnalyticsDTO analytics = AnalyticsDTO.builder()
                .riskDistribution(riskDistribution)
                .approvalRate(approvalRate)
                .monthlyStats(monthlyStats)
                .topHighRiskUsers(topHighRiskUsers)
                .build();

        return ResponseEntity.ok(ApiResponse.success(analytics, "Analytics retrieved"));
    }

    // â”€â”€ Users â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @GetMapping("/users")
    public ResponseEntity<ApiResponse<List<java.util.Map<String, Object>>>> getAllUsers() {
        List<java.util.Map<String, Object>> users = userRepository.findAll()
                .stream()
                .map(u -> {
                    java.util.Map<String, Object> map = new java.util.LinkedHashMap<>();
                    map.put("id", u.getId());
                    map.put("username", u.getRealUsername());
                    map.put("email", u.getEmail());
                    map.put("roles", u.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));
                    map.put("phoneNumber", u.getPhoneNumber());
                    map.put("address", u.getAddress());
                    map.put("enabled", u.isEnabled());
                    return map;
                })
                .collect(Collectors.toList());
        return ResponseEntity.ok(ApiResponse.success(users, "Users retrieved"));
    }

    /**
     * GET /api/admin/users/{userId}
     * Returns full user profile: user details + financial summary + loans + recent transactions.
     */
    @GetMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<UserProfileDTO>> getUserProfile(@PathVariable Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.NOT_FOUND, "User not found"));

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

        // Map loans to DTOs (inline mapping to avoid coupling to impl)
        List<LoanResponseDTO> loanDTOs = loans.stream().map(ln ->
                LoanResponseDTO.builder()
                        .id(ln.getId())
                        .loanAmount(ln.getLoanAmount())
                        .monthlyIncome(ln.getMonthlyIncome())
                        .monthlyExpense(ln.getMonthlyExpense())
                        .riskScore(ln.getRiskScore())
                        .riskLevel(ln.getRiskLevel())
                        .status(ln.getStatus())
                        .purpose(ln.getPurpose())
                        .adminNote(ln.getAdminNote())
                        .createdAt(ln.getCreatedAt())
                        .updatedAt(ln.getUpdatedAt())
                        .applicantEmail(ln.getUser().getEmail())
                        .applicantUsername(ln.getUser().getRealUsername())
                        .build()
        ).collect(Collectors.toList());

        // Recent 10 transactions
        List<Transaction> recentTx = transactionRepository.findByUserOrderByCreatedAtDesc(user)
                .stream().limit(10).collect(Collectors.toList());

        List<TransactionResponseDTO> txDTOs = recentTx.stream().map(t ->
                TransactionResponseDTO.builder()
                        .id(t.getId())
                        .type(t.getType())
                        .amount(t.getAmount())
                        .description(t.getDescription())
                        .transactionDate(t.getTransactionDate())
                        .createdAt(t.getCreatedAt())
                        .build()
        ).collect(Collectors.toList());

        UserProfileDTO profile = UserProfileDTO.builder()
                .id(user.getId())
                .username(user.getRealUsername())
                .email(user.getEmail())
                .phoneNumber(user.getPhoneNumber())
                .address(user.getAddress())
                .bio(user.getBio())
                .enabled(user.isEnabled())
                .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                .totalIncome(totalIncome)
                .totalExpenses(totalExpenses)
                .savingsBalance(savings)
                .totalTransactions(txCount)
                .latestRiskScore(latestRiskScore)
                .latestRiskLevel(latestRiskLevel)
                .loans(loanDTOs)
                .recentTransactions(txDTOs)
                .build();

        return ResponseEntity.ok(ApiResponse.success(profile, "User profile retrieved"));
    }

    // â”€â”€ Audit Logs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @GetMapping("/audit-logs")
    public ResponseEntity<ApiResponse<List<AuditLog>>> getAuditLogs() {
        return ResponseEntity.ok(ApiResponse.success(auditLogService.getAll(), "Audit logs retrieved"));
    }
}
