package cholog.auth.ui;

import cholog.auth.application.AuthService;
import cholog.auth.application.AuthorizationException;
import cholog.auth.dto.MemberResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class SessionLoginController {
    private static final String SESSION_KEY = "USER";
    private static final String USERNAME_FIELD = "email";
    private static final String PASSWORD_FIELD = "password";

    private final AuthService authService;

    public SessionLoginController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * ex) request sample
     * <p>
     * POST /login/session HTTP/1.1
     * content-type: application/x-www-form-urlencoded; charset=ISO-8859-1
     * host: localhost:55477
     * <p>
     * email=email@email.com&password=1234
     */
    @PostMapping("/login/session")
    public ResponseEntity<Void> sessionLogin(HttpServletRequest request, HttpSession session) {
        // TODO: HttpRequest로 받은 email과 password 추출
        Map<String, String[]> parameters = request.getParameterMap();
        String email = parameters.get(USERNAME_FIELD) != null ? parameters.get(USERNAME_FIELD)[0] : "";
        String password = parameters.get(PASSWORD_FIELD) != null ? parameters.get(PASSWORD_FIELD)[0] : "";

        if (authService.checkInvalidLogin(email, password)) {
            throw new AuthorizationException();
        }

        // TODO: Session에 인증 정보 저장 (key: SESSION_KEY, value: email값)
        session.setAttribute(SESSION_KEY, email);

        return ResponseEntity.ok().build();
    }

    /**
     * ex) request sample
     * <p>
     * GET /members/me/session HTTP/1.1
     * cookie: JSESSIONID=E7263AC9557EF658C888F02EEF840A19
     * accept: application/json
     */
    @GetMapping("/members/me/session")
    public ResponseEntity<MemberResponse> findMyInfo(HttpSession session) {
        // TODO: Session을 통해 인증 정보 조회 (key: SESSION_KEY)
        String email = (String) session.getAttribute(SESSION_KEY);
        if (email == null) {
            throw new AuthorizationException();
        }
        MemberResponse member = authService.findMember(email);
        return ResponseEntity.ok().body(member);
    }
}
