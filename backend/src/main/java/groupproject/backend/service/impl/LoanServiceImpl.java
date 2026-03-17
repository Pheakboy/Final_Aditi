package groupproject.backend.service.impl;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import jakarta.persistence.criteria.Predicate;

import groupproject.backend.dto.InstallmentPayRequestDTO;
import groupproject.backend.dto.LoanDecisionRequestDTO;
import groupproject.backend.dto.LoanInstallmentDTO;
import groupproject.backend.dto.LoanRequestDTO;
import groupproject.backend.dto.LoanResponseDTO;
import groupproject.backend.model.Loan;
import groupproject.backend.model.LoanDecision;
import groupproject.backend.model.LoanInstallment;
import groupproject.backend.model.LoanPayment;
import groupproject.backend.model.Transaction;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.LoanStatus;
import groupproject.backend.model.enums.NotificationType;
import groupproject.backend.model.enums.RiskLevel;
import groupproject.backend.model.enums.TransactionType;
import groupproject.backend.repository.LoanDecisionRepository;
import groupproject.backend.repository.LoanInstallmentRepository;
import groupproject.backend.repository.LoanPaymentRepository;
import groupproject.backend.repository.LoanRepository;
import groupproject.backend.repository.TransactionRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.PagedResponse;
import groupproject.backend.service.AuditLogService;
import groupproject.backend.service.LoanService;
import groupproject.backend.service.NotificationService;
import groupproject.backend.service.RiskScoringService;

@Service
public class LoanServiceImpl implements LoanService {

    private final LoanRepository loanRepository;
    private final LoanDecisionRepository loanDecisionRepository;
    private final LoanInstallmentRepository installmentRepository;
    private final LoanPaymentRepository loanPaymentRepository;
    private final TransactionRepository transactionRepository;
    private final UserRepository userRepository;
    private final RiskScoringService riskScoringService;
    private final AuditLogService auditLogService;
    private final NotificationService notificationService;

    public LoanServiceImpl(LoanRepository loanRepository,
                           LoanDecisionRepository loanDecisionRepository,
                           LoanInstallmentRepository installmentRepository,
                           LoanPaymentRepository loanPaymentRepository,
                           TransactionRepository transactionRepository,
                           UserRepository userRepository,
                           RiskScoringService riskScoringService,
                           AuditLogService auditLogService,
                           NotificationService notificationService) {
        this.loanRepository = loanRepository;
        this.loanDecisionRepository = loanDecisionRepository;
        this.installmentRepository = installmentRepository;
        this.loanPaymentRepository = loanPaymentRepository;
        this.transactionRepository = transactionRepository;
        this.userRepository = userRepository;
        this.riskScoringService = riskScoringService;
        this.auditLogService = auditLogService;
        this.notificationService = notificationService;
    }

    @Override
    @Transactional
    @SuppressWarnings("null")
    public ApiResponse<LoanResponseDTO> applyLoan(Authentication authentication, LoanRequestDTO request) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        long transactionCount = transactionRepository.countByUser(user);

        BigDecimal monthlyIncome = request.getMonthlyIncome();
        BigDecimal monthlyExpense = request.getMonthlyExpense();
        BigDecimal savings = monthlyIncome.subtract(monthlyExpense);

        double riskScore = riskScoringService.calculateRiskScore(monthlyIncome, monthlyExpense, transactionCount, savings);
        RiskLevel riskLevel = riskScoringService.determineRiskLevel(riskScore);

        BigDecimal interestRate = (request.getInterestRate() != null)
                ? request.getInterestRate() : new BigDecimal("0.12");
        Integer termMonths = (request.getTermMonths() != null)
                ? request.getTermMonths() : 12;

        Loan loan = Loan.builder()
                .user(user)
                .loanAmount(request.getLoanAmount())
                .monthlyIncome(monthlyIncome)
                .monthlyExpense(monthlyExpense)
                .riskScore(riskScore)
                .riskLevel(riskLevel)
                .status(LoanStatus.PENDING)
                .purpose(request.getPurpose())
                .interestRate(interestRate)
                .termMonths(termMonths)
                .build();

        Loan saved = loanRepository.save(loan);

        auditLogService.log("LOAN_APPLICATION", user.getEmail(),
                "Applied for loan of " + request.getLoanAmount() + ", risk: " + riskLevel + " (" + riskScore + ")");

        return ApiResponse.success(mapToDTO(saved), "Loan application submitted successfully");
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<List<LoanResponseDTO>> getMyLoans(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        List<LoanResponseDTO> loans = loanRepository.findByUserOrderByCreatedAtDesc(user)
                .stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());

        return ApiResponse.success(loans, "Loans retrieved");
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<LoanResponseDTO> getLoanByIdForUser(Authentication authentication, UUID loanId) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        Loan loan = loanRepository.findById(Objects.requireNonNull(loanId))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Loan not found"));
        if (!loan.getUser().getId().equals(user.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }
        return ApiResponse.success(mapToDTO(loan), "Loan retrieved");
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<List<LoanResponseDTO>> getAllLoans() {
        List<LoanResponseDTO> loans = loanRepository.findAllByOrderByCreatedAtDesc()
                .stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
        return ApiResponse.success(loans, "All loans retrieved");
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<List<LoanResponseDTO>> getPendingLoans() {
        List<LoanResponseDTO> loans = loanRepository.findByStatusOrderByCreatedAtDesc(LoanStatus.PENDING)
                .stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
        return ApiResponse.success(loans, "Pending loans retrieved");
    }

    @Override
    @Transactional
    @SuppressWarnings("null")
    public ApiResponse<LoanResponseDTO> decideLoan(Authentication authentication, UUID loanId, LoanDecisionRequestDTO request) {
        User admin = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        Loan loan = loanRepository.findById(Objects.requireNonNull(loanId, "Loan ID cannot be null"))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Loan not found"));

        if (loan.getStatus() != LoanStatus.PENDING) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Loan has already been decided");
        }

        LoanStatus decision;
        try {
            decision = LoanStatus.valueOf(request.getDecision().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid decision");
        }

        if (decision != LoanStatus.APPROVED && decision != LoanStatus.REJECTED) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid decision");
        }

        if (decision == LoanStatus.APPROVED) {
            loan.setStatus(LoanStatus.ACTIVE);
            loan.setStartDate(LocalDate.now());
            loanRepository.save(loan);
            generateInstallmentSchedule(loan);
        } else {
            loan.setStatus(LoanStatus.REJECTED);
        }

        loan.setAdminNote(request.getNote());
        loanRepository.save(loan);

        LoanDecision loanDecision = LoanDecision.builder()
                .loan(loan)
                .admin(admin)
                .decision(loan.getStatus() == LoanStatus.ACTIVE ? LoanStatus.APPROVED : LoanStatus.REJECTED)
                .note(request.getNote())
                .build();
        loanDecisionRepository.save(loanDecision);

        NotificationType notifType = (loan.getStatus() == LoanStatus.ACTIVE)
                ? NotificationType.LOAN_APPROVED : NotificationType.LOAN_REJECTED;
        String notifMsg = (loan.getStatus() == LoanStatus.ACTIVE)
                ? "Your loan of $" + loan.getLoanAmount() + " has been approved! Your installment schedule is now active."
                : "Your loan application of $" + loan.getLoanAmount() + " was rejected. Note: " + request.getNote();
        notificationService.sendToUser(loan.getUser(), "Loan Decision", notifMsg, notifType);

        auditLogService.log("LOAN_" + decision.name(), admin.getEmail(),
                "Loan " + loanId + " " + decision.name().toLowerCase() + " by admin");

        return ApiResponse.success(mapToDTO(loan), "Loan decision recorded");
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<PagedResponse<LoanResponseDTO>> getLoansFiltered(
            int page, int size, String status, String riskLevel, LocalDate fromDate, LocalDate toDate) {

        LoanStatus statusEnum = null;
        if (status != null && !status.isBlank()) {
            try { statusEnum = LoanStatus.valueOf(status.toUpperCase()); }
            catch (IllegalArgumentException ignored) {}
        }

        RiskLevel riskLevelEnum = null;
        if (riskLevel != null && !riskLevel.isBlank()) {
            try { riskLevelEnum = RiskLevel.valueOf(riskLevel.toUpperCase()); }
            catch (IllegalArgumentException ignored) {}
        }

        LocalDateTime from = fromDate != null ? fromDate.atStartOfDay() : null;
        LocalDateTime to   = toDate   != null ? toDate.atTime(23, 59, 59) : null;

        final LoanStatus finalStatus = statusEnum;
        final RiskLevel finalRiskLevel = riskLevelEnum;
        final LocalDateTime finalFrom = from;
        final LocalDateTime finalTo = to;

        Specification<Loan> spec = (root, query, cb) -> {
            if (query != null && !query.getResultType().equals(Long.class)) {
                root.fetch("user");
            }
            List<Predicate> predicates = new ArrayList<>();
            if (finalStatus != null)    predicates.add(cb.equal(root.get("status"), finalStatus));
            if (finalRiskLevel != null) predicates.add(cb.equal(root.get("riskLevel"), finalRiskLevel));
            if (finalFrom != null)      predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), finalFrom));
            if (finalTo != null)        predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), finalTo));
            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<Loan> loanPage = loanRepository.findAll(spec,
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));

        PagedResponse<LoanResponseDTO> paged = PagedResponse.<LoanResponseDTO>builder()
                .content(loanPage.getContent().stream().map(this::mapToDTO).collect(Collectors.toList()))
                .page(loanPage.getNumber())
                .size(loanPage.getSize())
                .totalElements(loanPage.getTotalElements())
                .totalPages(loanPage.getTotalPages())
                .last(loanPage.isLast())
                .build();

        return ApiResponse.success(paged, "Loans retrieved");
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<List<LoanInstallmentDTO>> getInstallments(Authentication authentication, UUID loanId) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        Loan loan = loanRepository.findById(Objects.requireNonNull(loanId))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Loan not found"));
        if (!loan.getUser().getId().equals(user.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }
        List<LoanInstallmentDTO> installments = installmentRepository
                .findByLoanOrderByInstallmentNumberAsc(loan)
                .stream()
                .map(this::mapInstallmentToDTO)
                .collect(Collectors.toList());
        return ApiResponse.success(installments, "Installments retrieved");
    }

    @Override
    @Transactional
    @SuppressWarnings("null")
    public ApiResponse<LoanInstallmentDTO> payInstallment(Authentication authentication, InstallmentPayRequestDTO request) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        LoanInstallment installment = installmentRepository
                .findById(Objects.requireNonNull(request.getInstallmentId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Installment not found"));

        if (!installment.getLoan().getUser().getId().equals(user.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }
        if (!"PENDING".equals(installment.getStatus())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Installment already paid");
        }

        BigDecimal paymentAmount = installment.getTotalAmount();
        BigDecimal income  = transactionRepository.sumAmountByUserAndType(user, TransactionType.INCOME);
        BigDecimal expense = transactionRepository.sumAmountByUserAndType(user, TransactionType.EXPENSE);
        BigDecimal balance = income.subtract(expense);

        if (balance.compareTo(paymentAmount) < 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Insufficient balance. Required: $" + paymentAmount + ", Available: $" + balance);
        }

        // Deduct via an EXPENSE transaction
        Transaction txn = Transaction.builder()
                .user(user)
                .type(TransactionType.EXPENSE)
                .amount(paymentAmount)
                .description("Loan installment #" + installment.getInstallmentNumber()
                        + " payment for loan " + installment.getLoan().getId())
                .build();
        transactionRepository.save(txn);

        installment.setStatus("PAID");
        installment.setPaidAt(LocalDateTime.now());
        installmentRepository.save(installment);

        LoanPayment loanPayment = LoanPayment.builder()
                .installment(installment)
                .user(user)
                .amount(paymentAmount)
                .paymentDate(LocalDateTime.now())
                .status("SUCCESS")
                .build();
        loanPaymentRepository.save(loanPayment);

        Loan loan = installment.getLoan();
        long remaining = installmentRepository.countByLoanAndStatus(loan, "PENDING");
        if (remaining == 0) {
            loan.setStatus(LoanStatus.COMPLETED);
            loanRepository.save(loan);
            notificationService.sendToUser(user, "Loan Completed! 🎉",
                    "Congratulations! You have fully repaid your loan of $" + loan.getLoanAmount() + ".",
                    NotificationType.INSTALLMENT_PAID);
        } else {
            notificationService.sendToUser(user, "Installment Paid",
                    "Installment #" + installment.getInstallmentNumber() + " of $" + paymentAmount
                            + " paid successfully. " + remaining + " installment(s) remaining.",
                    NotificationType.INSTALLMENT_PAID);
        }

        auditLogService.log("INSTALLMENT_PAID", user.getEmail(),
                "Paid installment #" + installment.getInstallmentNumber()
                        + " of $" + paymentAmount + " for loan " + loan.getId());

        return ApiResponse.success(mapInstallmentToDTO(installment), "Installment paid successfully");
    }

    // ─── Private Helpers ────────────────────────────────────────────────────────

    /**
     * Equal-principal amortization: fixed principal per month, decreasing interest.
     */
    private void generateInstallmentSchedule(Loan loan) {
        BigDecimal totalPrincipal = loan.getLoanAmount();
        int term = loan.getTermMonths();
        BigDecimal annualRate = loan.getInterestRate();
        BigDecimal monthlyRate = annualRate.divide(BigDecimal.valueOf(12), 10, RoundingMode.HALF_UP);

        BigDecimal principalPerMonth = totalPrincipal.divide(BigDecimal.valueOf(term), 4, RoundingMode.HALF_UP);
        BigDecimal remainingPrincipal = totalPrincipal;
        LocalDate startDate = loan.getStartDate();

        for (int i = 1; i <= term; i++) {
            BigDecimal interestAmount = remainingPrincipal.multiply(monthlyRate).setScale(4, RoundingMode.HALF_UP);
            BigDecimal totalAmount = principalPerMonth.add(interestAmount).setScale(4, RoundingMode.HALF_UP);
            LocalDate dueDate = startDate.plusMonths(i);

            LoanInstallment inst = LoanInstallment.builder()
                    .loan(loan)
                    .installmentNumber(i)
                    .dueDate(dueDate)
                    .principalAmount(principalPerMonth)
                    .interestAmount(interestAmount)
                    .totalAmount(totalAmount)
                    .status("PENDING")
                    .build();
            installmentRepository.save(inst);
            remainingPrincipal = remainingPrincipal.subtract(principalPerMonth);
        }
    }

    private LoanInstallmentDTO mapInstallmentToDTO(LoanInstallment i) {
        return LoanInstallmentDTO.builder()
                .id(i.getId())
                .installmentNumber(i.getInstallmentNumber())
                .dueDate(i.getDueDate())
                .principalAmount(i.getPrincipalAmount())
                .interestAmount(i.getInterestAmount())
                .totalAmount(i.getTotalAmount())
                .status(i.getStatus())
                .paidAt(i.getPaidAt())
                .build();
    }

    private LoanResponseDTO mapToDTO(Loan loan) {
        BigDecimal monthlyPayment = null;
        if (loan.getLoanAmount() != null && loan.getTermMonths() != null && loan.getInterestRate() != null) {
            BigDecimal monthlyRate = loan.getInterestRate()
                    .divide(BigDecimal.valueOf(12), 10, RoundingMode.HALF_UP);
            BigDecimal principalPerMonth = loan.getLoanAmount()
                    .divide(BigDecimal.valueOf(loan.getTermMonths()), 4, RoundingMode.HALF_UP);
            BigDecimal firstInterest = loan.getLoanAmount().multiply(monthlyRate)
                    .setScale(4, RoundingMode.HALF_UP);
            monthlyPayment = principalPerMonth.add(firstInterest).setScale(2, RoundingMode.HALF_UP);
        }

        return LoanResponseDTO.builder()
                .id(loan.getId())
                .loanAmount(loan.getLoanAmount())
                .monthlyIncome(loan.getMonthlyIncome())
                .monthlyExpense(loan.getMonthlyExpense())
                .riskScore(loan.getRiskScore())
                .riskLevel(loan.getRiskLevel())
                .status(loan.getStatus())
                .purpose(loan.getPurpose())
                .adminNote(loan.getAdminNote())
                .interestRate(loan.getInterestRate())
                .termMonths(loan.getTermMonths())
                .startDate(loan.getStartDate())
                .monthlyPayment(monthlyPayment)
                .createdAt(loan.getCreatedAt())
                .updatedAt(loan.getUpdatedAt())
                .applicantEmail(loan.getUser().getEmail())
                .applicantUsername(loan.getUser().getRealUsername())
                .build();
    }
}
