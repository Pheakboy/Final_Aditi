package groupproject.backend.repository;

import groupproject.backend.model.LoanPayment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface LoanPaymentRepository extends JpaRepository<LoanPayment, UUID> {
}
