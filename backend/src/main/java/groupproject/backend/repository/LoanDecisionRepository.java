package groupproject.backend.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import groupproject.backend.model.Loan;
import groupproject.backend.model.LoanDecision;

public interface LoanDecisionRepository extends JpaRepository<LoanDecision, UUID> {
    Optional<LoanDecision> findByLoan(Loan loan);
}
