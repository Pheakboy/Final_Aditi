package groupproject.backend.service;

import java.time.LocalDate;
import java.util.List;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import groupproject.backend.model.LoanInstallment;
import groupproject.backend.model.enums.NotificationType;
import groupproject.backend.repository.LoanInstallmentRepository;

@Component
public class PaymentReminderScheduler {

    private final LoanInstallmentRepository loanInstallmentRepository;
    private final NotificationService notificationService;

    public PaymentReminderScheduler(LoanInstallmentRepository loanInstallmentRepository,
                                    NotificationService notificationService) {
        this.loanInstallmentRepository = loanInstallmentRepository;
        this.notificationService = notificationService;
    }

    /** Runs daily at 9:00 AM — sends reminders for installments due within 3 days. */
    @Scheduled(cron = "0 0 9 * * *")
    public void sendPaymentReminders() {
        LocalDate today = LocalDate.now();
        LocalDate in3Days = today.plusDays(3);

        List<LoanInstallment> upcoming =
                loanInstallmentRepository.findPendingDueBetween(today.plusDays(1), in3Days);

        for (LoanInstallment inst : upcoming) {
            notificationService.sendToUser(
                    inst.getLoan().getUser(),
                    "Payment Reminder",
                    "Reminder: Your installment #" + inst.getInstallmentNumber()
                            + " of $" + inst.getTotalAmount()
                            + " is due on " + inst.getDueDate() + ".",
                    NotificationType.LOAN_REMINDER);
        }
    }
}
