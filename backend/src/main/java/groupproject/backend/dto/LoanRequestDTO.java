package groupproject.backend.dto;

import java.math.BigDecimal;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
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

    /** Annual interest rate as a decimal, e.g. 0.12 for 12%. Defaults to 12%. */
    @DecimalMin(value = "0.01", message = "Interest rate must be positive")
    private BigDecimal interestRate;

    /** Loan term in months. Must be 1–360. Defaults to 12. */
    @Min(value = 1, message = "Term must be at least 1 month")
    @Max(value = 360, message = "Term cannot exceed 360 months")
    private Integer termMonths;
}
