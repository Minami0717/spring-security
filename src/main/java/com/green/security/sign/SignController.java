package com.green.security.sign;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.green.security.CommonRes;
import com.green.security.config.security.otp.OtpRes;
import com.green.security.config.security.otp.TOTPTokenGenerator;
import com.green.security.sign.model.SignInResultDto;
import com.green.security.sign.model.SignUpResultDto;
import de.taimos.totp.TOTP;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/sign-api")
public class SignController {
    private final SignService SERVICE;
    private final TOTPTokenGenerator totp;

    //ApiParam은 문서 자동화를 위한 Swagger에서 쓰이는 어노테이션이고
    //RequestParam은 http 로부터 요청 온 정보를 받아오기 위한 스프링 어노테이션이다.

    @PostMapping("/sign-in")
    public SignInResultDto signIn(HttpServletRequest req, @RequestParam String id, @RequestParam String password) throws RuntimeException, JsonProcessingException {

        String ip = req.getRemoteAddr();
        log.info("[signIn] 로그인을 시도하고 있습니다. id: {}, pw: {}, ip: {}", id, password, ip);

        return SERVICE.signIn(id, password, ip);
    }

    @PostMapping("/sign-up")
    public SignUpResultDto signUp(@RequestParam String id
                                , @RequestParam String pw
                                , @RequestParam String nm
                                , @RequestParam String role) {
        log.info("[signUp] 회원가입을 수행합니다. id: {}, pw: {}, nm: {}, role: {}", id, pw, nm, role);
        SignUpResultDto dto = SERVICE.signUp(id, pw, nm, role);
        log.info("[signUp] 회원가입 완료 id: {}", id);
        return dto;
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<SignUpResultDto> refreshToken(HttpServletRequest req, @RequestParam String refreshToken) {
        SignUpResultDto dto = SERVICE.refreshToken(req, refreshToken);
        return dto == null ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null) : ResponseEntity.ok(dto);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest req) {
        SERVICE.logout(req);
        ResponseCookie responseCookie = ResponseCookie.from("refresh-token", "")
                .maxAge(0)
                .path("/")
                .build();

        return ResponseEntity
                .status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .build();
    }

    @GetMapping("/otp")
    public ResponseEntity<?> otp() {
        String secretKey = totp.generateSecretKey();
        System.out.println(secretKey);
        String account = "pirbak@google.com";
        String issuer = "otpTest";
        String barcodeUrl = totp.getGoogleAuthenticatorBarcode(secretKey, account, issuer);
        OtpRes res = OtpRes.builder().secretKey(secretKey).barcodeUrl(barcodeUrl).build();
        SERVICE.updSecretKey(1L, secretKey);
        return ResponseEntity.status(HttpStatus.OK).body(res);
    }

    @GetMapping("/otp-valid")
    public ResponseEntity<?> otpValid(@RequestParam String inputCode) {
        return ResponseEntity.status(HttpStatus.OK).body(SERVICE.otpValid(inputCode));
    }
}
