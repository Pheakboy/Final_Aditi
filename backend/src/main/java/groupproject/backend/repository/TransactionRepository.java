package groupproject.backend.repository;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import groupproject.backend.model.Transaction;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.TransactionType;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, UUID> {
    List<Transaction> findByUserOrderByCreatedAtDesc(User user);
    long countByUser(User user);

    @Query("SELECT COALESCE(SUM(t.amount), 0) FROM Transaction t WHERE t.user = :user AND t.type = :type")
    BigDecimal sumAmountByUserAndType(@Param("user") User user, @Param("type") TransactionType type);

    // Count distinct year-month combinations to compute average monthly income
    @Query(value = "SELECT COUNT(DISTINCT EXTRACT(YEAR FROM created_at) * 100 + EXTRACT(MONTH FROM created_at)) " +
                   "FROM transactions WHERE user_id = :userId AND type = 'INCOME'",
           nativeQuery = true)
    long countDistinctIncomeMonths(@Param("userId") Long userId);
}
