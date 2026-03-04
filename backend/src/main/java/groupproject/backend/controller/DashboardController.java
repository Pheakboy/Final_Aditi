package groupproject.backend.controller;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import groupproject.backend.dto.DashboardSummaryDTO;
import groupproject.backend.model.Loan;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.LoanStatus;
import groupproject.backend.model.enums.TransactionType;
import groupproject.backend.repository.LoanRepository;
import groupproject.backend.repository.TransactionRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.response.ApiResponse;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final UserRepository userRepository;
    private final TransactionRepository transactionRepository;
    private final LoanRepository loanRepository;

    public DashboardController(UserRepository userRepository,
                               TransactionRepository transactionRepository,
                               LoanRepository loanRepository) {
        this.userRepository = userRepository;
        this.transactionRepository = transactionRepository;
        this.loanRepository = loanRepository;
    }

    /**
     * GET /api/dashboard/summary
     * Returns financial summary for the currently authenticated user.
     */
    @GetMapping("/summary")
    public ResponseEntity<ApiResponse<DashboardSummaryDTO>> getSummary(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        // Financial calculations
        BigDecimal totalIncome = transactionRepository.sumAmountByUserAndType(user, TransactionType.INCOME);
        BigDecimal totalExpenses = transactionRepository.sumAmountByUserAndType(user, TransactionType.EXPENSE);
        if (totalIncome == null) totalIncome = BigDecimal.ZERO;
        if (totalExpenses == null) totalExpenses = BigDecimal.ZERO;
        BigDecimal savingsBalance = totalIncome.subtract(totalExpenses);

        // Average monthly income
        long distinctMonths = transactionRepository.countDistinctIncomeMonths(user.getId());
        BigDecimal avgMonthlyIncome = distinctMonths > 0
                ? totalIncome.divide(BigDecimal.valueOf(distinctMonths), 2, RoundingMode.HALF_UP)
                : BigDecimal.ZERO;

        long totalTransactions = transactionRepository.countByUser(user);

        // Loan stats
        List<Loan> userLoans = loanRepository.findByUserOrderByCreatedAtDesc(user);
        long totalLoans = userLoans.size();
        long pendingLoans = userLoans.stream().filter(l -> l.getStatus() == LoanStatus.PENDING).count();
        long approvedLoans = userLoans.stream().filter(l -> l.getStatus() == LoanStatus.APPROVED).count();
        long rejectedLoans = userLoans.stream().filter(l -> l.getStatus() == LoanStatus.REJECTED).count();

        // Latest risk info from most recent loan
        Double currentRiskScore = userLoans.isEmpty() ? null : userLoans.get(0).getRiskScore();
        String currentRiskLevel = (userLoans.isEmpty() || userLoans.get(0).getRiskLevel() == null)
                ? null : userLoans.get(0).getRiskLevel().name();

        DashboardSummaryDTO summary = DashboardSummaryDTO.builder()
                .totalIncome(totalIncome)
                .totalExpenses(totalExpenses)
                .savingsBalance(savingsBalance)
                .averageMonthlyIncome(avgMonthlyIncome)
                .totalTransactions(totalTransactions)
                .currentRiskScore(currentRiskScore)
                .currentRiskLevel(currentRiskLevel)
                .totalLoans(totalLoans)
                .pendingLoans(pendingLoans)
                .approvedLoans(approvedLoans)
                .rejectedLoans(rejectedLoans)
                .build();

        return ResponseEntity.ok(ApiResponse.success(summary, "Dashboard summary retrieved"));
    }
}
