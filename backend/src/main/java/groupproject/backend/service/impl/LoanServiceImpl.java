package groupproject.backend.service.impl;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

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
import groupproject.backend.service.LoanService;
import groupproject.backend.service.RiskScoringService;

@Service
public class LoanServiceImpl implements LoanService {

    private final LoanRepository loanRepository;
    private final LoanDecisionRepository loanDecisionRepository;
    private final TransactionRepository transactionRepository;
    private final UserRepository userRepository;
    private final RiskScoringService riskScoringService;

    public LoanServiceImpl(LoanRepository loanRepository,
                           LoanDecisionRepository loanDecisionRepository,
                           TransactionRepository transactionRepository,
                           UserRepository userRepository,
                           RiskScoringService riskScoringService) {
        this.loanRepository = loanRepository;
        this.loanDecisionRepository = loanDecisionRepository;
        this.transactionRepository = transactionRepository;
        this.userRepository = userRepository;
        this.riskScoringService = riskScoringService;
    }

    @Override
    @Transactional
    public ApiResponse<LoanResponseDTO> applyLoan(Authentication authentication, LoanRequestDTO request) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

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

        Loan saved = loanRepository.save(loan);

        return ApiResponse.success(mapToDTO(saved), "Loan application submitted successfully");
    }

    @Override
    public ApiResponse<List<LoanResponseDTO>> getMyLoans(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<LoanResponseDTO> loans = loanRepository.findByUserOrderByCreatedAtDesc(user)
                .stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());

        return ApiResponse.success(loans, "Loans retrieved");
    }

    @Override
    public ApiResponse<List<LoanResponseDTO>> getAllLoans() {
        List<LoanResponseDTO> loans = loanRepository.findAllByOrderByCreatedAtDesc()
                .stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());

        return ApiResponse.success(loans, "All loans retrieved");
    }

    @Override
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
                .orElseThrow(() -> new RuntimeException("User not found"));

        Loan loan = loanRepository.findById(loanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Loan not found"));

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

        loanDecisionRepository.save(loanDecision);

        return ApiResponse.success(mapToDTO(loan), "Loan decision recorded");
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
                .applicantUsername(loan.getUser().getUsername())
                .build();
    }
}
