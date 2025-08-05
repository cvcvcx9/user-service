# User Service

## 🚀 프로젝트 개요

이 프로젝트는 마이크로서비스 아키텍처의 사용자 인증 및 권한 부여를 담당하는 `User Service`입니다. Spring Boot를 기반으로 구축되었으며, 로컬 이메일/비밀번호 인증과 Google OAuth2 로그인을 지원합니다. JWT(JSON Web Token)를 사용하여 인증을 처리하며, 보안 강화를 위해 액세스 토큰과 리프레시 토큰을 분리하여 관리합니다. 웹 클라이언트와 모바일 앱 클라이언트의 특성을 고려하여 토큰 전달 방식을 다르게 제공합니다.

## ✨ 주요 기능

*   **사용자 관리:**
    *   로컬 계정 회원가입 (`/api/auth/register/mobile`, `/api/auth/register/web`)
    *   이메일 기반 사용자 조회
*   **인증:**
    *   로컬 이메일/비밀번호 로그인 (`/api/auth/login/mobile`, `/api/auth/login/web`)
    *   Google OAuth2 로그인 (`/api/auth/google/mobile`, `/api/auth/google/web`)
*   **토큰 관리:**
    *   액세스 토큰 및 리프레시 토큰 발급
    *   리프레시 토큰을 이용한 액세스 토큰 갱신 (`/api/auth/refresh/mobile`, `/api/auth/refresh/web`)
*   **클라이언트별 토큰 전달 방식 분리:**
    *   **모바일 앱:** 액세스 토큰과 리프레시 토큰 모두 응답 본문(JSON)으로 반환.
    *   **웹 클라이언트:** 액세스 토큰은 응답 본문으로, 리프레시 토큰은 `HttpOnly`, `Secure` 쿠키로 설정하여 반환.
*   **보안:**
    *   BCrypt를 이용한 비밀번호 해싱
    *   JWT 기반 인증 (짧은 액세스 토큰, 긴 리프레시 토큰)

## 🛠️ 기술 스택

*   **백엔드:** Java 17, Spring Boot 3.x
*   **데이터베이스:** H2 Database (개발/테스트용 인메모리 DB)
*   **인증/권한:** Spring Security, JJWT (JSON Web Token)
*   **유틸리티:** Lombok
*   **빌드 도구:** Gradle

## 🚀 시작하기

### 전제 조건

*   Java 17 이상
*   Gradle
*   IntelliJ IDEA (권장) 또는 다른 IDE

### 프로젝트 설정

1.  **프로젝트 클론:**
    ```bash
    git clone <your-repository-url>
    cd user-service
    ```
2.  **Gradle 의존성 다운로드:**
    IntelliJ IDEA에서 프로젝트를 열면 Gradle이 자동으로 의존성을 다운로드합니다. 수동으로 하려면:
    ```bash
    ./gradlew build
    ```
3.  **환경 설정 (`src/main/resources/application-dev.yml`)**
    `src/main/resources/application-dev.yml` 파일을 열고 다음 JWT 관련 설정을 추가하거나 확인합니다. `secret` 값은 Base64로 인코딩된 32바이트 이상의 문자열이어야 합니다.

    ```yaml
    jwt:
      secret: your_base64_encoded_secret_key_for_dev # 실제 사용 시 안전한 키로 변경 필요
      expiration: 3600000 # 액세스 토큰 만료 시간 (밀리초, 예: 1시간)
      refreshExpiration: 604800000 # 리프레시 토큰 만료 시간 (밀리초, 예: 7일)
    ```
    **주의:** 실제 운영 환경에서는 이 `secret` 값을 환경 변수나 외부 설정 관리 시스템을 통해 관리해야 합니다.

### 애플리케이션 실행

IntelliJ IDEA에서 `UserServiceApplication`을 실행합니다. `application-dev.yml` 프로파일을 활성화하려면 `Run/Debug Configurations`에서 `Active profiles`에 `dev`를 추가합니다.

## 🧪 API 테스트 (Postman)

애플리케이션이 실행 중인 상태에서 Postman을 사용하여 다음 엔드포인트를 테스트할 수 있습니다. (기본 포트: 8080)

### 1. 회원가입 (Registration)

*   **로컬 계정 회원가입 (모바일 앱용)**
    *   `POST` `http://localhost:8080/api/auth/register/mobile`
    *   **Body (JSON):**
        ```json
        {
            "email": "mobile_user@example.com",
            "password": "password123"
        }
        ```
    *   **응답:** `201 Created`와 함께 `accessToken`, `refreshToken` (JSON 본문)

*   **로컬 계정 회원가입 (웹 클라이언트용)**
    *   `POST` `http://localhost:8080/api/auth/register/web`
    *   **Body (JSON):**
        ```json
        {
            "email": "web_user@example.com",
            "password": "password123"
        }
        ```
    *   **응답:** `201 Created`와 함께 `accessToken` (JSON 본문), `refreshToken` (HttpOnly 쿠키)

### 2. 로그인 (Login)

*   **로컬 계정 로그인 (모바일 앱용)**
    *   `POST` `http://localhost:8080/api/auth/login/mobile`
    *   **Body (JSON):**
        ```json
        {
            "email": "mobile_user@example.com",
            "password": "password123"
        }
        ```
    *   **응답:** `200 OK`와 함께 `accessToken`, `refreshToken` (JSON 본문)

*   **로컬 계정 로그인 (웹 클라이언트용)**
    *   `POST` `http://localhost:8080/api/auth/login/web`
    *   **Body (JSON):**
        ```json
        {
            "email": "web_user@example.com",
            "password": "password123"
        }
        ```
    *   **응답:** `200 OK`와 함께 `accessToken` (JSON 본문), `refreshToken` (HttpOnly 쿠키)

### 3. 토큰 갱신 (Refresh Token)

*   **토큰 갱신 (모바일 앱용)**
    *   `POST` `http://localhost:8080/api/auth/refresh/mobile`
    *   **Body (JSON):**
        ```json
        {
            "refreshToken": "이전 로그인/회원가입 시 받은 refreshToken 값"
        }
        ```
    *   **응답:** `200 OK`와 함께 새로운 `accessToken`, 기존 `refreshToken` (JSON 본문)

*   **토큰 갱신 (웹 클라이언트용)**
    *   `POST` `http://localhost:8080/api/auth/refresh/web`
    *   **Headers:** (Postman이 `refreshToken` 쿠키를 자동으로 포함)
    *   **Body:** `none`
    *   **응답:** `200 OK`와 함께 새로운 `accessToken` (JSON 본문)

### 4. Google 로그인

Google 로그인은 실제 OAuth2 흐름을 시뮬레이션해야 하므로 Postman에서 직접 테스트하기는 복잡합니다. 일반적으로는 Google OAuth 2.0 Playground 등에서 발급받은 `access_token` 또는 `id_token`을 사용하여 테스트할 수 있습니다.

*   **Google 로그인 (모바일 앱용)**
    *   `POST` `http://localhost:8080/api/auth/google/mobile`
    *   **Body (JSON):**
        ```json
        {
            "token": "Google에서 발급받은 access_token 또는 id_token"
        }
        ```
    *   **응답:** `200 OK`와 함께 `accessToken`, `refreshToken` (JSON 본문)

*   **Google 로그인 (웹 클라이언트용)**
    *   `POST` `http://localhost:8080/api/auth/google/web`
    *   **Body (JSON):**
        ```json
        {
            "token": "Google에서 발급받은 access_token 또는 id_token"
        }
        ```
    *   **응답:** `200 OK`와 함께 `accessToken` (JSON 본문), `refreshToken` (HttpOnly 쿠키)

## 🤝 기여 (Contributing)

프로젝트 기여에 대한 내용은 여기에 추가할 수 있습니다.

## 📄 라이선스 (License)

프로젝트 라이선스에 대한 내용은 여기에 추가할 수 있습니다.