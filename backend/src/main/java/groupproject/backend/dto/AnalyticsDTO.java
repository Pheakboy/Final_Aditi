package groupproject.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AnalyticsDTO {

    private RiskDistribution riskDistribution;
    private ApprovalRate approvalRate;
    private List<MonthlyStats> monthlyStats;
    private List<HighRiskUser> topHighRiskUsers;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class RiskDistribution {
        private long low;
        private long medium;
        private long high;
        private long total;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ApprovalRate {
        private long approved;
        private long rejected;
        private long pending;
        private long total;
        private double approvalPercentage;
        private double rejectionPercentage;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class MonthlyStats {
        private int year;
        private int month;
        private long count;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class HighRiskUser {
        private String email;
        private String username;
        private double riskScore;
    }
}
