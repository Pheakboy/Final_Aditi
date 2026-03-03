package groupproject.backend.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import groupproject.backend.model.Loan;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.LoanStatus;

public interface LoanRepository extends JpaRepository<Loan, UUID> {
    List<Loan> findByUserOrderByCreatedAtDesc(User user);
    List<Loan> findByStatusOrderByCreatedAtDesc(LoanStatus status);
    List<Loan> findAllByOrderByCreatedAtDesc();
}
