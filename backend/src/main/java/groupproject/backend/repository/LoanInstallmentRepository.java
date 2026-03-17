package groupproject.backend.repository;

import groupproject.backend.model.Loan;
import groupproject.backend.model.LoanInstallment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public interface LoanInstallmentRepository extends JpaRepository<LoanInstallment, UUID> {

    List<LoanInstallment> findByLoanOrderByInstallmentNumberAsc(Loan loan);

    /** For the reminder scheduler — find PENDING installments due within a date window */
    @Query("SELECT i FROM LoanInstallment i WHERE i.status = 'PENDING' AND i.dueDate BETWEEN :from AND :to")
    List<LoanInstallment> findPendingDueBetween(
            @Param("from") LocalDate from,
            @Param("to") LocalDate to);

    long countByLoanAndStatus(Loan loan, String status);
}
