package groupproject.backend.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import groupproject.backend.model.Loan;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.LoanStatus;
import groupproject.backend.model.enums.RiskLevel;

@Repository
public interface LoanRepository extends JpaRepository<Loan, UUID>, JpaSpecificationExecutor<Loan> {
    List<Loan> findByUserOrderByCreatedAtDesc(User user);
    List<Loan> findByStatusOrderByCreatedAtDesc(LoanStatus status);
    List<Loan> findAllByOrderByCreatedAtDesc();

    long countByStatus(LoanStatus status);
    long countByRiskLevel(RiskLevel riskLevel);

    // PostgreSQL-compatible: use native query with EXTRACT
    @Query(value = "SELECT EXTRACT(MONTH FROM created_at) AS month, EXTRACT(YEAR FROM created_at) AS year, COUNT(*) AS count " +
           "FROM loans GROUP BY EXTRACT(YEAR FROM created_at), EXTRACT(MONTH FROM created_at) " +
           "ORDER BY EXTRACT(YEAR FROM created_at) DESC, EXTRACT(MONTH FROM created_at) DESC",
           nativeQuery = true)
    List<Object[]> findMonthlyLoanCounts();

    // Fixed: ORDER BY DESC to get highest-risk users first
    @Query("SELECT l.user, l.riskScore FROM Loan l WHERE l.riskLevel = 'HIGH' ORDER BY l.riskScore DESC")
    List<Object[]> findTopHighRiskUsers();

    // Paginated + filtered query for admin panel
    @Query("SELECT l FROM Loan l WHERE " +
           "(:status IS NULL OR l.status = :status) AND " +
           "(:riskLevel IS NULL OR l.riskLevel = :riskLevel) AND " +
           "(:fromDate IS NULL OR l.createdAt >= :fromDate) AND " +
           "(:toDate IS NULL OR l.createdAt <= :toDate) " +
           "ORDER BY l.createdAt DESC")
    Page<Loan> findByFilters(
            @Param("status") LoanStatus status,
            @Param("riskLevel") RiskLevel riskLevel,
            @Param("fromDate") LocalDateTime fromDate,
            @Param("toDate") LocalDateTime toDate,
            Pageable pageable);
}
