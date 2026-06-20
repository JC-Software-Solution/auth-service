package jcss.soft.com.auth_service.repository;

import jcss.soft.com.auth_service.model.User;
import jcss.soft.com.auth_service.spel.IUserSpel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    @Query("SELECT u.email as email, u.firstname as firstname, u.lastname as lastname FROM User u WHERE u.email = :email")
    Optional<IUserSpel> findUserByEmail(String email);


}
