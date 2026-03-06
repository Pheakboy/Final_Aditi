package groupproject.backend.repository;

import java.util.List;
import java.util.UUID;

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

    @Query("SELECT l FROM Loan l JOIN FETCH l.user WHERE l.user = :user ORDER BY l.createdAt DESC")
    List<Loan> findByUserOrderByCreatedAtDesc(@Param("user") User user);

    @Query("SELECT l FROM Loan l JOIN FETCH l.user WHERE l.status = :status ORDER BY l.createdAt DESC")
    List<Loan> findByStatusOrderByCreatedAtDesc(@Param("status") LoanStatus status);

    @Query("SELECT l FROM Loan l JOIN FETCH l.user ORDER BY l.createdAt DESC")
    List<Loan> findAllByOrderByCreatedAtDesc();

    long countByStatus(LoanStatus status);
    long countByRiskLevel(RiskLevel riskLevel);
    long countByUser(User user);

    // JPQL: works with both H2 (dev) and PostgreSQL (prod)
    @Query("SELECT MONTH(l.createdAt), YEAR(l.createdAt), COUNT(l) FROM Loan l " +
           "GROUP BY YEAR(l.createdAt), MONTH(l.createdAt) " +
           "ORDER BY YEAR(l.createdAt) DESC, MONTH(l.createdAt) DESC")
    List<Object[]> findMonthlyLoanCounts();

    // Use enum parameter instead of string literal to avoid Hibernate 6 type mismatch
    @Query("SELECT l.user, l.riskScore FROM Loan l WHERE l.riskLevel = :riskLevel ORDER BY l.riskScore DESC")
    List<Object[]> findTopHighRiskUsers(@Param("riskLevel") RiskLevel riskLevel);
}
