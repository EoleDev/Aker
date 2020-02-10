-- MySQL Script generated by MySQL Workbench
-- Mon 10 Feb 2020 11:31:01 AM CET
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema aker
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema aker
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `aker` DEFAULT CHARACTER SET utf8mb4 ;
USE `aker` ;

-- -----------------------------------------------------
-- Table `aker`.`usergroups`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `aker`.`usergroups` ;

CREATE TABLE IF NOT EXISTS `aker`.`usergroups` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `name_UNIQUE` (`name` ASC))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4;


-- -----------------------------------------------------
-- Table `aker`.`users`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `aker`.`users` ;

CREATE TABLE IF NOT EXISTS `aker`.`users` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(255) NOT NULL,
  `keyfile` VARCHAR(255) NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `username_UNIQUE` (`username` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `aker`.`users_usergroups`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `aker`.`users_usergroups` ;

CREATE TABLE IF NOT EXISTS `aker`.`users_usergroups` (
  `usersId` INT UNSIGNED NOT NULL,
  `usergroupsId` INT UNSIGNED NOT NULL,
  PRIMARY KEY (`usersId`, `usergroupsId`),
  INDEX `fk_users_usergroups_2_idx` (`usergroupsId` ASC),
  CONSTRAINT `fk_users_usergroups_1`
    FOREIGN KEY (`usersId`)
    REFERENCES `aker`.`users` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `fk_users_usergroups_2`
    FOREIGN KEY (`usergroupsId`)
    REFERENCES `aker`.`usergroups` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `aker`.`hostgroups`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `aker`.`hostgroups` ;

CREATE TABLE IF NOT EXISTS `aker`.`hostgroups` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `name_UNIQUE` (`name` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `aker`.`hosts`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `aker`.`hosts` ;

CREATE TABLE IF NOT EXISTS `aker`.`hosts` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  `hostname` VARCHAR(255) NOT NULL,
  `port` VARCHAR(25) NULL DEFAULT 22,
  `key` VARCHAR(255) NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `name_UNIQUE` (`name` ASC),
  UNIQUE INDEX `hostname_UNIQUE` (`hostname` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `aker`.`hosts_usergroups`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `aker`.`hosts_usergroups` ;

CREATE TABLE IF NOT EXISTS `aker`.`hosts_usergroups` (
  `hostsId` INT UNSIGNED NOT NULL,
  `usergroupsId` INT UNSIGNED NOT NULL,
  PRIMARY KEY (`hostsId`, `usergroupsId`),
  INDEX `fk_hosts_usergroups_2_idx` (`usergroupsId` ASC),
  CONSTRAINT `fk_hosts_usergroups_1`
    FOREIGN KEY (`hostsId`)
    REFERENCES `aker`.`hosts` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `fk_hosts_usergroups_2`
    FOREIGN KEY (`usergroupsId`)
    REFERENCES `aker`.`usergroups` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `aker`.`hosts_hostgroups`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `aker`.`hosts_hostgroups` ;

CREATE TABLE IF NOT EXISTS `aker`.`hosts_hostgroups` (
  `hostsId` INT UNSIGNED NOT NULL,
  `hostgroupsId` INT UNSIGNED NOT NULL,
  PRIMARY KEY (`hostsId`, `hostgroupsId`),
  INDEX `fk_hosts_hostgroups_2_idx` (`hostgroupsId` ASC),
  CONSTRAINT `fk_hosts_hostgroups_1`
    FOREIGN KEY (`hostsId`)
    REFERENCES `aker`.`hosts` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `fk_hosts_hostgroups_2`
    FOREIGN KEY (`hostgroupsId`)
    REFERENCES `aker`.`hostgroups` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
