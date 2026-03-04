package groupproject.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DashboardSummaryDTO {
    private BigDecimal totalIncome;
    private BigDecimal totalExpenses;
    private BigDecimal savingsBalance;
    private BigDecimal averageMonthlyIncome;
    private long totalTransactions;
    private Double currentRiskScore;
    private String currentRiskLevel;
    private long totalLoans;
    private long pendingLoans;
    private long approvedLoans;
    private long rejectedLoans;
}
