package groupproject.backend.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import groupproject.backend.model.Transaction;
import groupproject.backend.model.User;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, UUID> {
    List<Transaction> findByUserOrderByCreatedAtDesc(User user);
    long countByUser(User user);
}
