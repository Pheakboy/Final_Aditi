package groupproject.backend.repository;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import groupproject.backend.model.Loan;
import groupproject.backend.model.LoanInstallment;

public interface LoanInstallmentRepository extends JpaRepository<LoanInstallment, UUID> {

    List<LoanInstallment> findByLoanOrderByInstallmentNumberAsc(Loan loan);

    /** Native SQL delete — bypasses Hibernate cache and FK ordering issues. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query(value = "DELETE FROM loan_installments WHERE loan_id = :loanId", nativeQuery = true)
    void deleteAllByLoanId(@Param("loanId") UUID loanId);

    @Modifying
    @Query("DELETE FROM LoanInstallment i WHERE i.loan = :loan")
    void deleteAllByLoan(@Param("loan") Loan loan);

    /** For the reminder scheduler — find PENDING installments due within a date window */
    @Query("SELECT i FROM LoanInstallment i WHERE i.status = 'PENDING' AND i.dueDate BETWEEN :from AND :to")
    List<LoanInstallment> findPendingDueBetween(
            @Param("from") LocalDate from,
            @Param("to") LocalDate to);

    long countByLoanAndStatus(Loan loan, String status);
}
