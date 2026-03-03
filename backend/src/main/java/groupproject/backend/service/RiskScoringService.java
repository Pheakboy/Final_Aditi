package groupproject.backend.service;

import java.math.BigDecimal;

import groupproject.backend.model.enums.RiskLevel;

public interface RiskScoringService {
    double calculateRiskScore(BigDecimal monthlyIncome, BigDecimal monthlyExpense, long transactionCount, BigDecimal savings);
    RiskLevel determineRiskLevel(double riskScore);
}
