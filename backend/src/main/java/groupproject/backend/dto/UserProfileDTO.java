package groupproject.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileDTO {
    private Long id;
    private String username;
    private String email;
    private String phoneNumber;
    private String address;
    private String bio;
    private boolean enabled;
    private Set<String> roles;

    // Financial summary
    private BigDecimal totalIncome;
    private BigDecimal totalExpenses;
    private BigDecimal savingsBalance;
    private long totalTransactions;

    // Latest risk info from most recent loan
    private Double latestRiskScore;
    private String latestRiskLevel;

    // Loan history
    private List<LoanResponseDTO> loans;

    // Recent transactions (last 10)
    private List<TransactionResponseDTO> recentTransactions;
}
