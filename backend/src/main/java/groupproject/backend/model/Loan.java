package groupproject.backend.model;

import groupproject.backend.model.enums.LoanStatus;
import groupproject.backend.model.enums.RiskLevel;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "loans")
public class Loan {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "loan_amount", nullable = false)
    private BigDecimal loanAmount;

    @Column(name = "monthly_income", nullable = false)
    private BigDecimal monthlyIncome;

    @Column(name = "monthly_expense", nullable = false)
    private BigDecimal monthlyExpense;

    @Column(name = "risk_score")
    private Double riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level")
    private RiskLevel riskLevel;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private LoanStatus status = LoanStatus.PENDING;

    private String purpose;

    @Column(name = "admin_note")
    private String adminNote;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
