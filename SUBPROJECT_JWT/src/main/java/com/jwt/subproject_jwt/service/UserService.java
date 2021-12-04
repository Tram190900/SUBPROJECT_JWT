package com.jwt.subproject_jwt.service;

import com.jwt.subproject_jwt.authen.UserPrincipal;
import com.jwt.subproject_jwt.enitity.User;

import java.util.List;


public interface UserService {
    User createUser(User user);
    UserPrincipal findByUsername(String username);
    List<User> findAll();
    //UserPrincipal getUserByData();
//    User getByUserName(String userName);
//    User addUser(User user);
    //UserPrincipal login(String userName);
}
