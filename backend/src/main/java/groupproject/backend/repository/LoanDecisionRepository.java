package groupproject.backend.repository;

import groupproject.backend.model.Loan;
import groupproject.backend.model.LoanDecision;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface LoanDecisionRepository extends JpaRepository<LoanDecision, UUID> {
    Optional<LoanDecision> findByLoan(Loan loan);
    List<LoanDecision> findByLoanOrderByDecidedAtDesc(Loan loan);
}
