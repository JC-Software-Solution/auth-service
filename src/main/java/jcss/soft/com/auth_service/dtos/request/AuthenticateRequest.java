package jcss.soft.com.auth_service.dtos.request;


import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthenticateRequest {

    private String email;

    private String password;

}