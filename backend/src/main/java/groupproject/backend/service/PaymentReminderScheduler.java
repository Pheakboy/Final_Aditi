package groupproject.backend.service;

import groupproject.backend.model.LoanInstallment;
import groupproject.backend.model.enums.NotificationType;
import groupproject.backend.repository.LoanInstallmentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.List;

/**
 * Runs every day at 08:00 and sends LOAN_REMINDER notifications
 * to borrowers whose next installment is due within 3 days.
 */
@Component
public class PaymentReminderScheduler {

    private static final Logger log = LoggerFactory.getLogger(PaymentReminderScheduler.class);

    private final LoanInstallmentRepository installmentRepository;
    private final NotificationService notificationService;

    public PaymentReminderScheduler(LoanInstallmentRepository installmentRepository,
                                    NotificationService notificationService) {
        this.installmentRepository = installmentRepository;
        this.notificationService = notificationService;
    }

    @Scheduled(cron = "0 0 8 * * *")
    public void sendPaymentReminders() {
        LocalDate today = LocalDate.now();
        LocalDate in3Days = today.plusDays(3);

        List<LoanInstallment> upcoming = installmentRepository.findPendingDueBetween(today, in3Days);
        log.info("[Scheduler] Sending {} payment reminders for {}", upcoming.size(), today);

        for (LoanInstallment installment : upcoming) {
            String msg = "⏰ Reminder: Your loan installment #" + installment.getInstallmentNumber()
                    + " of $" + installment.getTotalAmount()
                    + " is due on " + installment.getDueDate() + ". Please ensure sufficient balance.";

            notificationService.sendToUser(
                    installment.getLoan().getUser(),
                    "Payment Reminder",
                    msg,
                    NotificationType.LOAN_REMINDER
            );
        }
    }
}
