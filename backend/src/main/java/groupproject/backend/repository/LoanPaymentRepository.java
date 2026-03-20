package groupproject.backend.repository;

import groupproject.backend.model.LoanPayment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface LoanPaymentRepository extends JpaRepository<LoanPayment, UUID> {

    /** Delete all payments whose installment belongs to the given loan. */
    @Modifying
    @Query(value = "DELETE FROM loan_payments WHERE installment_id IN " +
            "(SELECT id FROM loan_installments WHERE loan_id = :loanId)", nativeQuery = true)
    void deleteAllByLoanId(@Param("loanId") UUID loanId);
}
