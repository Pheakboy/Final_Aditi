package groupproject.backend.service.impl;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
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
import java.util.ArrayList;

import groupproject.backend.dto.LoanDecisionRequestDTO;
import groupproject.backend.dto.LoanRequestDTO;
import groupproject.backend.dto.LoanResponseDTO;
import groupproject.backend.model.Loan;
import groupproject.backend.model.LoanDecision;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.LoanStatus;
import groupproject.backend.model.enums.RiskLevel;
import groupproject.backend.repository.LoanDecisionRepository;
import groupproject.backend.repository.LoanRepository;
import groupproject.backend.repository.TransactionRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.PagedResponse;
import groupproject.backend.service.AuditLogService;
import groupproject.backend.service.LoanService;
import groupproject.backend.service.RiskScoringService;

@Service
public class LoanServiceImpl implements LoanService {

    private final LoanRepository loanRepository;
    private final LoanDecisionRepository loanDecisionRepository;
    private final TransactionRepository transactionRepository;
    private final UserRepository userRepository;
    private final RiskScoringService riskScoringService;
    private final AuditLogService auditLogService;

    public LoanServiceImpl(LoanRepository loanRepository,
                           LoanDecisionRepository loanDecisionRepository,
                           TransactionRepository transactionRepository,
                           UserRepository userRepository,
                           RiskScoringService riskScoringService,
                           AuditLogService auditLogService) {
        this.loanRepository = loanRepository;
        this.loanDecisionRepository = loanDecisionRepository;
        this.transactionRepository = transactionRepository;
        this.userRepository = userRepository;
        this.riskScoringService = riskScoringService;
        this.auditLogService = auditLogService;
    }

    @Override
    @Transactional
    public ApiResponse<LoanResponseDTO> applyLoan(Authentication authentication, LoanRequestDTO request) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        long transactionCount = transactionRepository.countByUser(user);

        BigDecimal monthlyIncome = request.getMonthlyIncome();
        BigDecimal monthlyExpense = request.getMonthlyExpense();
        BigDecimal savings = monthlyIncome.subtract(monthlyExpense);

        double riskScore = riskScoringService.calculateRiskScore(monthlyIncome, monthlyExpense, transactionCount, savings);
        RiskLevel riskLevel = riskScoringService.determineRiskLevel(riskScore);

        Loan loan = Loan.builder()
                .user(user)
                .loanAmount(request.getLoanAmount())
                .monthlyIncome(monthlyIncome)
                .monthlyExpense(monthlyExpense)
                .riskScore(riskScore)
                .riskLevel(riskLevel)
                .status(LoanStatus.PENDING)
                .purpose(request.getPurpose())
                .build();

        Loan saved = Objects.requireNonNull(loanRepository.save(loan), "Failed to save loan");

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
    public ApiResponse<LoanResponseDTO> decideLoan(Authentication authentication, UUID loanId, LoanDecisionRequestDTO request) {
        User admin = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        Loan loan = loanRepository.findById(Objects.requireNonNull(loanId, "Loan ID cannot be null"))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Loan not found"));

        // Guard: only allow deciding PENDING loans
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

        loan.setStatus(decision);
        loan.setAdminNote(request.getNote());
        loanRepository.save(loan);

        LoanDecision loanDecision = LoanDecision.builder()
                .loan(loan)
                .admin(admin)
                .decision(decision)
                .note(request.getNote())
                .build();

        Objects.requireNonNull(loanDecisionRepository.save(loanDecision), "Failed to save loan decision");

        auditLogService.log("LOAN_" + decision.name(), admin.getEmail(),
                "Loan " + loanId + " " + decision.name().toLowerCase() + " by admin");

        return ApiResponse.success(mapToDTO(loan), "Loan decision recorded");
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<PagedResponse<LoanResponseDTO>> getLoansFiltered(
            int page, int size,
            String status,
            String riskLevel,
            LocalDate fromDate,
            LocalDate toDate) {

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
            // Only JOIN FETCH on the data query, not on the COUNT query
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

    private LoanResponseDTO mapToDTO(Loan loan) {
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
                .createdAt(loan.getCreatedAt())
                .updatedAt(loan.getUpdatedAt())
                .applicantEmail(loan.getUser().getEmail())
                .applicantUsername(loan.getUser().getRealUsername())
                .build();
    }
}
