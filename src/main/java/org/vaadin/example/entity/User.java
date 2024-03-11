package org.vaadin.example.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.vaadin.example.Role;

import java.util.Set;


@Getter
@Setter
@Entity
@Table(name = "FVMADM_USER", schema = "EKP_MONITOR")
public class User extends AbstractEntity {

    private String username;
    private String name;
    @JsonIgnore
    private String hashedPassword;
    @Enumerated(EnumType.STRING)
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "FVMADM_USER_ROLES", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "roles")
    private Set<Role> roles;
    private int is_ad;
}
