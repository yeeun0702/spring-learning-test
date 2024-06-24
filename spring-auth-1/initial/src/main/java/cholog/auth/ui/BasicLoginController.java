package cholog.auth.ui;

import cholog.auth.application.AuthService;
import cholog.auth.application.AuthorizationException;
import cholog.auth.dto.AuthInfo;
import cholog.auth.dto.MemberResponse;
import cholog.auth.infrastructure.AuthorizationExtractor;
import cholog.auth.infrastructure.BasicAuthorizationExtractor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BasicLoginController {
    private final AuthService authService;
    private final AuthorizationExtractor<AuthInfo> authorizationExtractor;

    // AuthService를 주입받고, BasicAuthorizationExtractor를 초기화하는 생성자
    public BasicLoginController(AuthService authService) {
        this.authService = authService;
        this.authorizationExtractor = new BasicAuthorizationExtractor();
    }

    /**
     * ex) request sample
     * <p>
     * GET /members/me/basic HTTP/1.1
     * authorization: Basic ZW1haWxAZW1haWwuY29tOjEyMzQ=
     * accept: application/json
     */
    @GetMapping("/members/me/basic")
    public ResponseEntity<MemberResponse> findMyInfo(HttpServletRequest request) {
        // TODO: authorization 헤더의 Basic 값에 있는 email과 password 추출 (hint: authorizationExtractor 사용)
        AuthInfo authInfo = authorizationExtractor.extract(request);

        // authInfo가 null인 경우, 인증 예외를 발생시킴
        if (authInfo == null) {
            throw new AuthorizationException();
        }

        String email = authInfo.getEmail();
        String password = authInfo.getPassword();

        // 이메일과 패스워드가 유효하지 않은 경우, 인증 예외를 발생시킴
        if (authService.checkInvalidLogin(email, password)) {
            throw new AuthorizationException();
        }

        // 인증이 성공하면, AuthService를 통해 회원 정보를 조회하고, 응답으로 반환
        MemberResponse member = authService.findMember(email);
        return ResponseEntity.ok().body(member);
    }
}
