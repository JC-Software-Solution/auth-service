package jcss.soft.com.auth_service.dtos.response;


public record ResponseObject(
        int status,
        String message,
        Object data
) {

}
