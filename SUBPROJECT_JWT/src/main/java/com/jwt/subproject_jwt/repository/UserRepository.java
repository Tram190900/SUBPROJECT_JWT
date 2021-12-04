package com.jwt.subproject_jwt.repository;

import com.jwt.subproject_jwt.enitity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository
        extends JpaRepository<User, Long> {

    User findByUsername(String username);

    //User getUserByData();
}
