CREATE TABLE `malware_signatures` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(255) NOT NULL,
  `signature` BLOB NOT NULL,
  UNIQUE (`name`),  -- Ensure malware names are unique
  INDEX (`signature`(20))  -- Indexing for faster search within BLOB type
);

CREATE TABLE `admins` (
  `username` VARCHAR(255) NOT NULL PRIMARY KEY,
  `password_hash` CHAR(60) NOT NULL
);

CREATE TABLE `file_checks` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `file_name` VARCHAR(255) NOT NULL,
  `checked_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `is_infected` TINYINT(1) NOT NULL,
  `user_ip` VARCHAR(45) NULL
);

#intial malware signatures
INSERT INTO malware_signatures (name, signature) VALUES ('MalwareXYZ', UNHEX('D41D8CD98F00B204E9800998ECF8427E'));
INSERT INTO malware_signatures (name, signature) VALUES ('TrojanABC', UNHEX('AABBCD98F00B204E9800998ECF8427F'));
#username: admin  password:123123123
INSERT INTO admins (username, password_hash) VALUES ('admin', '$2y$10$DaFdIlCkIUk7LjAKGN5AlORkE6ak.HyB5NMQ4eQrUkqqqsEqSWw12');
