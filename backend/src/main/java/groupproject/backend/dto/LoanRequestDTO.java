package groupproject.backend.dto;

import java.math.BigDecimal;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class LoanRequestDTO {
    @NotNull(message = "Loan amount is required")
    @DecimalMin(value = "1.00", message = "Loan amount must be greater than 0")
    private BigDecimal loanAmount;

    @NotNull(message = "Monthly income is required")
    @DecimalMin(value = "0.00", message = "Monthly income cannot be negative")
    private BigDecimal monthlyIncome;

    @NotNull(message = "Monthly expense is required")
    @DecimalMin(value = "0.00", message = "Monthly expense cannot be negative")
    private BigDecimal monthlyExpense;

    private String purpose;
}
