package cholog.auth.ui;

import cholog.auth.application.AuthService;
import cholog.auth.dto.MemberResponse;
import cholog.auth.dto.TokenRequest;
import cholog.auth.dto.TokenResponse;
import cholog.auth.infrastructure.AuthorizationExtractor;
import cholog.auth.infrastructure.BearerAuthorizationExtractor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenLoginController {
    private final AuthService authService;
    private final AuthorizationExtractor<String> authorizationExtractor;

    public TokenLoginController(AuthService authService) {
        this.authService = authService;
        this.authorizationExtractor = new BearerAuthorizationExtractor();
    }

    /**
     * ex) request sample
     * <p>
     * POST /login/token HTTP/1.1
     * accept: application/json
     * content-type: application/json; charset=UTF-8
     * <p>
     * {
     * "email": "email@email.com",
     * "password": "1234"
     * }
     */
    @PostMapping("/login/token")
    public ResponseEntity<TokenResponse> tokenLogin(@RequestBody TokenRequest tokenRequest) {
        // TODO: email, password 정보를 가진 TokenRequest 값을 메서드 파라미터로 받아오기 (hint: @RequestBody)
        // @RequestBody를 사용하여 클라이언트에서 전송된 JSON 데이터를 TokenRequest 객체로 변환
        TokenResponse tokenResponse = authService.createToken(tokenRequest);
        return ResponseEntity.ok().body(tokenResponse);
    }

    /**
     * ex) request sample
     * <p>
     * GET /members/me/token HTTP/1.1
     * authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlbWFpbEBlbWFpbC5jb20iLCJpYXQiOjE2MTAzNzY2NzIsImV4cCI6MTYxMDM4MDI3Mn0.Gy4g5RwK1Nr7bKT1TOFS4Da6wxWh8l97gmMQDgF8c1E
     * accept: application/json
     */
    @GetMapping("/members/me/token")
    public ResponseEntity<MemberResponse> findMyInfo(HttpServletRequest request) {
        // TODO: authorization 헤더의 Bearer 값을 추출 (hint: authorizationExtractor 사용)
        // authorizationExtractor를 사용하여 요청 헤더에서 Bearer 토큰을 추출
        String token = authorizationExtractor.extract(request);
        MemberResponse member = authService.findMemberByToken(token);
        return ResponseEntity.ok().body(member);
    }
}
