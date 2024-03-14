# Spring-boot에서의 JWT 사용
Spring Boot에서 JWT를 사용하는 방법에 대한 레포지토리입니다.

# JWT

## JWT 구성

- Header
    - typ: 토큰의 타입을 지정한다.
    - alg: signature를 해싱하기 위한 알고리즘을 저장한다.
- Payload
    - Registered Claim: 토큰에 대한 정보를 담는다.
    - Public Claim: 사용자 정의 클레임으로, 시스템에 필요한 정보를 담는다.
    - Private Claim: 시스템에 필요한 정보 중 특정 도메인에서만 필요한 정보를 담는다.
- Signature
    - 헤더와 페이로드의 내용이 유효하고 변조되지 않았음을 검증한다.

## 구현 과정

1. 서버가 클라이언트에게 사용자의 로그인 정보를 요청받는다.
2. 해당 사용자의 정보를 검증한다.
3. **Header**를 생성한다:
”typ”과 “alg”을 JSON 형식으로 작성한다.
4. **Payload**를 생성한다:
사용자 ID, 권한 등의 클레임을 페이로드에 담는다.
5. 헤더와 페이로드를 Base64로 인코딩한다.
6. **Signature**을 생성한다:
헤더와 페이로드를 인코딩한 값에 지정된 알고리즘과 비밀 키를 사용하여 해싱한 값을 저장한다.
7. **JWT**를 생성한다:
생성된 헤더, 페이로드, 서명을 조합하여 JWT를 생성한다. 각 부분은 .으로 구분되어 하나의 문자열로 합쳐진다.
8. **JWT**를 클라이언트에게 반환한다:
클라이언트는 이후 요청에 이 JWT를 포함하여 서버에 전달한다.

# 구현하기

## 의존성 및 플러그인 추가

### build.gradle

```gradle
dependencies {
    // Spring security
    implementation 'org.springframework.boot:spring-boot-starter-security'
    // JWT
    implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
    implementation 'io.jsonwebtoken:jjwt-impl:0.11.5'
    implementation 'io.jsonwebtoken:jjwt-jackson:0.11.5'
}
```

- `Spring security`: 비밀번호 암호화를 사용하기 위한 PasswordEncoder를 포함하는 의존성이다.
- `jjwt-api`: JWT를 생성하고 파싱하는 데 필요한 인터페이스와 기본적인 클래스들이 포함되어 있다.(ex: JwtBuilder(), Claims())
- `jjwt-impl`: jjwt-api의 구현체를 포함하고 있어 jjwt-api의 인터페이스를 구현하여 실제 JWT를 생성하고 파싱하는 기능을 제공한다.
- `jjwt-jackson`: Jackson 라이브러리를 사용하여 JWT를 JSON 형식으로 변환하는데 사용된다.

### application.yaml

```yaml
application:
  security:
    jwt:
      secret: whifa3452efwihn15ajkdvawuocnawclejhfgrow84afwjenoh43829r2huifnjkae
      expiration: 10800
      refresh: 75600
```

실제로 이렇게 하면 안되고 secret key의 경우 환경 변수로 빼주어야한다.

- `header`: JWT를 실어보낼 때 사용될 헤더의 이름이다.
- `secret`: 서명을 생성하고 검증할 때 사용되는 비밀키. HS256 알고리즘의 사용을 위해 secret이 256비트 이상이 되도록 설정한다.
- `expiration`: access token의 만료시간으로 초단위로 표기한다.
- `refresh`: refresh token의 만료시간으로 초단위로 표기한다.

## JWTAuthenticationFilter

```java
@Component
@AllArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    private final JWTService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Autherization");
        final String jwt;
        final String userEmail;

        // Bearer 스키마를 사용하였는지 판단
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);

        // UserEmail 조회 및 토큰 유효성 확인
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            var isTokenValid = tokenRepository.findByToken(jwt)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);
            if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

- Header 추출하여 JWT 여부를 확인한다.(Bearer인 경우 추출한다)
    - JWT 표준규약은 Bearer 스키마를 사용하도록 권장하기 때문이다.
- UserEmail을 통해 user 정보를 조회하고 토큰의 유효성을 확인한다.

# JWTService

```java
@Service
public class JWTService {
    public String extractUsername(String token) {
        return null;
    }

    private Key getSignInKey() {
        byte[] keyByte = Decoders.BASE64.decode("${application.security.jwt.secret}");
        return Keys.hmacShaKeyFor(keyByte);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims); // 특정 클레임만 반환
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder() // JWT 파서 빌더 생성
                .setSigningKey(getSignInKey()) // 서명 검증에 사용될 키 생성
                .build() // JWT 파서 생성
                .parseClaimsJws(token) // 토큰 파싱 및 서명 검증
                .getBody(); // 클레임 추출
    }

    // 유저 정보를 통해 토큰 발급
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // 유저 정보 및 추가 클레임을 통해 토큰 발급
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, Long.parseLong("${application.security.jwt.expiration}"));
    }

    // JWT 토큰 생성
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims) // 추가 클레임 정보 설정
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // 유효한 토큰인지 검증
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // 만료된 토큰인지 체크
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 토큰에서 만료시간 추출
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
```

- 토큰 파싱 및 클레임 추출
- 토큰 발급
- 토큰 검증
- 토큰 만료여부 확인
- 토큰 만료시간 추출

# ApplicationConfig

```java

```
