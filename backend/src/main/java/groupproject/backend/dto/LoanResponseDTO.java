package groupproject.backend.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

import groupproject.backend.model.enums.LoanStatus;
import groupproject.backend.model.enums.RiskLevel;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoanResponseDTO {
    private UUID id;
    private BigDecimal loanAmount;
    private BigDecimal monthlyIncome;
    private BigDecimal monthlyExpense;
    private Double riskScore;
    private RiskLevel riskLevel;
    private LoanStatus status;
    private String purpose;
    private String adminNote;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String applicantEmail;
    private String applicantUsername;
}
