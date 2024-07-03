CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    firstname VARCHAR(100) NOT NULL,
    lastname VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    phone_number BIGINT UNSIGNED UNIQUE NOT NULL,
    password VARCHAR(256) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    isBlocked TINYINT(1) DEFAULT 0,
    address VARCHAR(200),
    refreshToken VARCHAR(512),
    passwordCreatedAt DATETIME,
    passwordChangedAt DATETIME,
    passwordResetToken VARCHAR(512),
    passwordResetExpires BIGINT,
    otp VARCHAR(256),
    otpExpiresAt BIGINT,
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE USERS_DETAILS(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT CONSTRAINT FK_user_id REFERENCES users(id),
    firstname VARCHAR(100) NOT NULL REFERENCES users(firstname),
    lastname VARCHAR(100) NOT NULL REFERENCES users(lastname),
    email VARCHAR(120) UNIQUE NOT NULL REFERENCES users(email),
    phone_number BIGINT UNSIGNED UNIQUE NOT NULL users(phone_number),
    prfile_photo VARCHAR(255),
    designation VARCHAR(120),
    reporting_manager_id BIGINT CONSTRAINT FK_reporting_manager_id REFERENCES USERS_DETAILS(id),
    access_resources JSON
)