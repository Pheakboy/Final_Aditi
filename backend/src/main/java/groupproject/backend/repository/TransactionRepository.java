package groupproject.backend.repository;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import groupproject.backend.model.Transaction;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.TransactionType;

public interface TransactionRepository extends JpaRepository<Transaction, UUID> {
    List<Transaction> findByUserOrderByCreatedAtDesc(User user);
    long countByUser(User user);

    @Query("SELECT COALESCE(SUM(t.amount), 0) FROM Transaction t WHERE t.user = :user AND t.type = :type")
    BigDecimal sumAmountByUserAndType(@Param("user") User user, @Param("type") TransactionType type);
}
