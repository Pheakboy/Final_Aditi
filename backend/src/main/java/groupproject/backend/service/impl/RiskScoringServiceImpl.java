package groupproject.backend.service.impl;

import java.math.BigDecimal;

import org.springframework.stereotype.Service;

import groupproject.backend.model.enums.RiskLevel;
import groupproject.backend.service.RiskScoringService;

@Service
public class RiskScoringServiceImpl implements RiskScoringService {

    private static final double INCOME_WEIGHT = 0.3;
    private static final double EXPENSE_WEIGHT = 0.2;
    private static final double TRANSACTION_WEIGHT = 0.2;
    private static final double SAVINGS_WEIGHT = 0.3;

    @Override
    public double calculateRiskScore(BigDecimal monthlyIncome, BigDecimal monthlyExpense, long transactionCount, BigDecimal savings) {
        double incomeScore = calculateIncomeScore(monthlyIncome);
        double expenseScore = calculateExpenseScore(monthlyIncome, monthlyExpense);
        double transactionScore = calculateTransactionScore(transactionCount);
        double savingsScore = calculateSavingsScore(savings);

        return (incomeScore * INCOME_WEIGHT)
                + (expenseScore * EXPENSE_WEIGHT)
                + (transactionScore * TRANSACTION_WEIGHT)
                + (savingsScore * SAVINGS_WEIGHT);
    }

    @Override
    public RiskLevel determineRiskLevel(double riskScore) {
        if (riskScore >= 80) {
            return RiskLevel.LOW;
        } else if (riskScore >= 50) {
            return RiskLevel.MEDIUM;
        } else {
            return RiskLevel.HIGH;
        }
    }

    private double calculateIncomeScore(BigDecimal monthlyIncome) {
        if (monthlyIncome.compareTo(BigDecimal.valueOf(1000)) >= 0) {
            return 100;
        } else if (monthlyIncome.compareTo(BigDecimal.valueOf(500)) >= 0) {
            return 70;
        } else {
            return 40;
        }
    }

    private double calculateExpenseScore(BigDecimal monthlyIncome, BigDecimal monthlyExpense) {
        if (monthlyIncome.compareTo(BigDecimal.ZERO) == 0) {
            return 30;
        }
        BigDecimal ratio = monthlyExpense.divide(monthlyIncome, 10, java.math.RoundingMode.HALF_UP);
        if (ratio.compareTo(BigDecimal.valueOf(0.5)) < 0) {
            return 100;
        } else if (ratio.compareTo(BigDecimal.valueOf(0.8)) < 0) {
            return 70;
        } else {
            return 30;
        }
    }

    private double calculateTransactionScore(long transactionCount) {
        if (transactionCount > 30) {
            return 100;
        } else if (transactionCount > 10) {
            return 70;
        } else {
            return 40;
        }
    }

    private double calculateSavingsScore(BigDecimal savings) {
        if (savings.compareTo(BigDecimal.valueOf(300)) >= 0) {
            return 100;
        } else if (savings.compareTo(BigDecimal.valueOf(100)) >= 0) {
            return 70;
        } else {
            return 40;
        }
    }
}
