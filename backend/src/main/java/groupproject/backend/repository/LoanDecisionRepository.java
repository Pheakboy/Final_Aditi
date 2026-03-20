package groupproject.backend.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import groupproject.backend.model.Loan;
import groupproject.backend.model.LoanDecision;

public interface LoanDecisionRepository extends JpaRepository<LoanDecision, UUID> {
    Optional<LoanDecision> findByLoan(Loan loan);
    List<LoanDecision> findByLoanOrderByDecidedAtDesc(Loan loan);

    /** Native SQL delete — bypasses UNIQUE constraint ordering issues. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query(value = "DELETE FROM loan_decisions WHERE loan_id = :loanId", nativeQuery = true)
    void deleteAllByLoanId(@Param("loanId") UUID loanId);

    @Modifying
    @Query("DELETE FROM LoanDecision d WHERE d.loan = :loan")
    void deleteAllByLoan(@Param("loan") Loan loan);
}
