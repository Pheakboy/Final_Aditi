package groupproject.backend.config;

import groupproject.backend.model.Role;
import groupproject.backend.model.User;
import groupproject.backend.repository.RoleRepository;
import groupproject.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements ApplicationRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seedRoles();
        seedAdminUser();
    }

    private void seedRoles() {
        if (roleRepository.findByName("USER").isEmpty()) {
            Role userRole = new Role();
            userRole.setName("USER");
            roleRepository.save(userRole);
            log.info("Seeded role: USER");
        }

        if (roleRepository.findByName("ADMIN").isEmpty()) {
            Role adminRole = new Role();
            adminRole.setName("ADMIN");
            roleRepository.save(adminRole);
            log.info("Seeded role: ADMIN");
        }
    }

    private void seedAdminUser() {
        String adminEmail = "admin@loanapp.com";

        if (userRepository.existsByEmail(adminEmail)) {
            return;
        }

        Role adminRole = roleRepository.findByName("ADMIN")
                .orElseThrow(() -> new RuntimeException("ADMIN role not found after seeding"));
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("USER role not found after seeding"));

        User admin = new User();
        admin.setUsername("Admin");
        admin.setEmail(adminEmail);
        admin.setPassword(passwordEncoder.encode("admin123"));
        admin.setEnabled(true);
        admin.setRoles(Set.of(adminRole, userRole));

        userRepository.save(admin);
        log.info("Seeded default admin user: {} (password: admin123)", adminEmail);
    }
}
