package com.green.security.sign;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.green.security.CommonRes;
import com.green.security.config.RedisService;
import com.green.security.config.security.AuthenticationFacade;
import com.green.security.config.security.JwtTokenProvider;
import com.green.security.config.security.UserDetailsMapper;
import com.green.security.config.security.model.RedisJwtVo;
import com.green.security.config.security.model.UserEntity;
import com.green.security.config.security.model.UserTokenEntity;
import com.green.security.config.security.otp.TOTP;
import com.green.security.sign.model.SignInResultDto;
import com.green.security.sign.model.SignUpResultDto;
import com.green.security.sign.model.UserUpdDto;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class SignService {
    private final UserDetailsMapper MAPPER;
    private final JwtTokenProvider JWT_PROVIDER;
    private final PasswordEncoder PW_ENCODER;
    private final RedisService redisService;
    private final AuthenticationFacade facade;
    private final ObjectMapper objectMapper;

    public SignUpResultDto signUp(String id, String pw, String nm, String role) {
        log.info("[getSignUpResult] signDataHandler로 회원 정보 요청");
        UserEntity user = UserEntity.builder()
                .uid(id)
                .upw(PW_ENCODER.encode(pw))
                .name(nm)
                .role(String.format("ROLE_%s", role))
                .build();
        int result = MAPPER.save(user);
        SignUpResultDto dto = new SignUpResultDto();

        if(result == 1) {
            log.info("[getSignUpResult] 정상 처리 완료");
            setSuccessResult(dto);
        } else {
            log.info("[getSignUpResult] 실패 처리 완료");
            setFailResult(dto);
        }
        return dto;
    }

    public SignInResultDto signIn(String id, String password, String ip) throws RuntimeException, JsonProcessingException {
        log.info("[getSignInResult] signDataHandler로 회원 정보 요청");
        UserEntity user = MAPPER.getByUid(id);

        log.info("[getSignInResult] id: {}", id);

        log.info("[getSignInResult] 패스워드 비교");
        if(!PW_ENCODER.matches(password, user.getUpw())) {
            throw new RuntimeException("비밀번호 다름");
        }
        log.info("[getSignInResult] 패스워드 일치");

        String redisKey = String.format("RT(%s):%s:%s", "Server", user.getIuser(), ip);
        if (redisService.getValues(redisKey) != null) {
            redisService.deleteValues(redisKey);
        }

        log.info("[getSignInResult] access_token 객체 생성");
        String accessToken = JWT_PROVIDER.generateJwtToken(String.valueOf(user.getIuser()), Collections.singletonList(user.getRole()), JWT_PROVIDER.ACCESS_TOKEN_VALID_MS, JWT_PROVIDER.ACCESS_KEY);
        String refreshToken = JWT_PROVIDER.generateJwtToken(String.valueOf(user.getIuser()), Collections.singletonList(user.getRole()), JWT_PROVIDER.REFRESH_TOKEN_VALID_MS, JWT_PROVIDER.REFRESH_KEY);

        RedisJwtVo redisJwtVo = RedisJwtVo.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        String value = objectMapper.writeValueAsString(redisJwtVo);
        redisService.setValues(redisKey, value);

//        UserTokenEntity tokenEntity = UserTokenEntity.builder()
//                .iuser(user.getIuser())
//                .accessToken(accessToken)
//                .refreshToken(refreshToken)
//                .ip(ip)
//                .build();
//
//        int result = MAPPER.updUserToken(tokenEntity);

        log.info("[getSignInResult] SignInResultDto 객체 생성");
        SignInResultDto dto = SignInResultDto.builder()
                                .accessToken(accessToken)
                                .refreshToken(refreshToken)
                                .build();

        log.info("[getSignInResult] SignInResultDto 객체 값 주입");
        setSuccessResult(dto);
        return dto;
    }

    public SignInResultDto refreshToken(HttpServletRequest req, String refreshToken) throws RuntimeException {
        if(!(JWT_PROVIDER.isValidateToken(refreshToken, JWT_PROVIDER.REFRESH_KEY))) {
            return null;
        }

        String ip = req.getRemoteAddr();
        String accessToken = JWT_PROVIDER.resolveToken(req, JWT_PROVIDER.TOKEN_TYPE);
        Claims claims = JWT_PROVIDER.getClaims(refreshToken, JWT_PROVIDER.REFRESH_KEY);
        if(claims == null) {
            return null;
        }

        String strIuser = claims.getSubject();
        Long iuser = Long.valueOf(strIuser);

        String redisKey = String.format("RT(%s):%s:%s", "Server", iuser, ip);
        String value = redisService.getValues(redisKey);
        if (value == null) {
            return null;
        }

        try {
            RedisJwtVo redisJwtVo = objectMapper.readValue(value, RedisJwtVo.class);
            if (!redisJwtVo.getAccessToken().equals(accessToken) || !redisJwtVo.getRefreshToken().equals(refreshToken)) {
                return null;
            }

            List<String> roles = (List<String>)claims.get("roles");
            String reAccessToken = JWT_PROVIDER.generateJwtToken(strIuser, roles, JWT_PROVIDER.ACCESS_TOKEN_VALID_MS, JWT_PROVIDER.ACCESS_KEY);

            RedisJwtVo updateRedisJwtVo = RedisJwtVo.builder()
                    .accessToken(reAccessToken)
                    .refreshToken(redisJwtVo.getRefreshToken())
                    .build();
            String updateValue = objectMapper.writeValueAsString(updateRedisJwtVo);
            redisService.setValues(redisKey, updateValue);

            return SignInResultDto.builder()
                    .accessToken(reAccessToken)
                    .refreshToken(refreshToken)
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

//        UserTokenEntity p = UserTokenEntity.builder()
//                .iuser(iuser)
//                .ip(ip)
//                .build();
//        UserTokenEntity selResult = MAPPER.selUserToken(p);
//        if(selResult == null || !(selResult.getAccessToken().equals(accessToken) && selResult.getRefreshToken().equals(refreshToken))) {
//            return null;
//        }
//
//        String reAccessToken = JWT_PROVIDER.generateJwtToken(strIuser, roles, JWT_PROVIDER.ACCESS_TOKEN_VALID_MS, JWT_PROVIDER.ACCESS_KEY);
//        UserTokenEntity tokenEntity = UserTokenEntity.builder()
//                .iuser(iuser)
//                .ip(ip)
//                .accessToken(reAccessToken)
//                .refreshToken(refreshToken)
//                .build();
//
//        int updResult = MAPPER.updUserToken(tokenEntity);
//
//        return SignInResultDto.builder()
//                .accessToken(reAccessToken)
//                .refreshToken(refreshToken)
//                .build();
    }

    public void logout(HttpServletRequest req) {
        String accessToken = JWT_PROVIDER.resolveToken(req, JWT_PROVIDER.TOKEN_TYPE);
        Long iuser = facade.getLoginUserPk();
        String ip = req.getRemoteAddr();

        String redisKey = String.format("RT(%s):%s:%s", "Server", iuser, ip);
        String refreshTokenInRedis = redisService.getValues(redisKey);
        if (refreshTokenInRedis != null) {
            redisService.deleteValues(redisKey);
        }

        long expiration = JWT_PROVIDER.getTokenExpirationTime(accessToken, JWT_PROVIDER.ACCESS_KEY) -
                LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
        log.info("date-getTime(): {}", new Date().getTime());
        log.info("localDateTime-getTime(): {}", LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli());

        redisService.setValuesWithTimeout(accessToken, "logout", expiration);
    }

    public int updSecretKey(Long iuser, String secretKey) {
        UserUpdDto dto = new UserUpdDto();
        dto.setIuser(iuser);
        dto.setSecretKey(secretKey);

        return MAPPER.updSecretKey(dto);
    }

    public boolean otpValid(String inputCode) {
        UserEntity entity = MAPPER.getByUid("id");
        String code = getTOTPCode(entity.getSecretKey());
        return code.equals(inputCode);
    }

    // OTP 검증 요청 때마다 개인키로 OTP 생성
    private String getTOTPCode(String secretKey) {
        Base32 base32 = new Base32();
        // 실제로는 로그인한 회원에게 생성된 개인키가 필요합니다.
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return TOTP.getOTP(hexKey);
    }

    private void setSuccessResult(SignUpResultDto result) {
        result.setSuccess(true);
        result.setCode(CommonRes.SUCCESS.getCode());
        result.setMsg(CommonRes.SUCCESS.getMsg());
    }

    private void setFailResult(SignUpResultDto result) {
        result.setSuccess(false);
        result.setCode(CommonRes.FAIL.getCode());
        result.setMsg(CommonRes.FAIL.getMsg());
    }
}

