-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Počítač: localhost
-- Vygenerováno: Stř 04. úno 2015, 11:17
-- Verze serveru: 5.5.38-0ubuntu0.14.04.1
-- Verze PHP: 5.5.9-1ubuntu4.3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Databáze: `tahoe`
--

-- --------------------------------------------------------

--
-- Struktura tabulky `access_list`
--

CREATE TABLE IF NOT EXISTS `access_list` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `number` int(11) DEFAULT NULL,
  `action` enum('permit','deny') DEFAULT 'permit',
  `protocol` varchar(32) DEFAULT NULL,
  `ip_source` int(11) NOT NULL,
  `ip_destination` int(11) NOT NULL,
  `ttl` int(11) DEFAULT NULL,
  `filter_id` int(11) NOT NULL,
  `ports_id` int(11) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `fk_access_list_ip_networks_idx` (`ip_source`),
  KEY `fk_access_list_ip_networks1_idx` (`ip_destination`),
  KEY `fk_access_list_filter1_idx` (`filter_id`),
  KEY `fk_access_list_ports1_idx` (`ports_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=4 ;

--
-- Vypisuji data pro tabulku `access_list`
--

INSERT INTO `access_list` (`id`, `number`, `action`, `protocol`, `ip_source`, `ip_destination`, `ttl`, `filter_id`, `ports_id`) VALUES
(3, NULL, 'permit', 'TCP,UDP', 1, 2, NULL, 1, 1);

-- --------------------------------------------------------

--
-- Struktura tabulky `analyzer`
--

CREATE TABLE IF NOT EXISTS `analyzer` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) DEFAULT NULL,
  `description` varchar(45) DEFAULT NULL,
  `src` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- Vypisuji data pro tabulku `analyzer`
--

INSERT INTO `analyzer` (`id`, `name`, `description`, `src`) VALUES
(1, 'VoIP', 'Analyzer for VoIP', '/var/analyzer/voip.c');

-- --------------------------------------------------------

--
-- Struktura tabulky `application`
--

CREATE TABLE IF NOT EXISTS `application` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) DEFAULT NULL,
  `active_flag` tinyint(1) DEFAULT NULL,
  `certificate_id` int(11) NOT NULL,
  `analyzer_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_application_certificates1_idx` (`certificate_id`),
  KEY `fk_application_analyzer1_idx` (`analyzer_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- Vypisuji data pro tabulku `application`
--

INSERT INTO `application` (`id`, `name`, `active_flag`, `certificate_id`, `analyzer_id`) VALUES
(1, 'VoIP monitoring', NULL, 1, 1);

-- --------------------------------------------------------

--
-- Struktura tabulky `certificate`
--

CREATE TABLE IF NOT EXISTS `certificate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) DEFAULT NULL,
  `root_cert_path` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- Vypisuji data pro tabulku `certificate`
--

INSERT INTO `certificate` (`id`, `name`, `root_cert_path`) VALUES
(1, 'cert1', 'datacert1');

-- --------------------------------------------------------

--
-- Struktura tabulky `filter`
--

CREATE TABLE IF NOT EXISTS `filter` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) DEFAULT NULL,
  `type` varchar(45) DEFAULT NULL,
  `application_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_policy_map_policy_map1_idx` (`application_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=4 ;

--
-- Vypisuji data pro tabulku `filter`
--

INSERT INTO `filter` (`id`, `name`, `type`, `application_id`) VALUES
(1, 'filter1', NULL, 1),
(3, 'filter2', NULL, 1);

-- --------------------------------------------------------

--
-- Struktura tabulky `filter_has_nbar_protocol`
--

CREATE TABLE IF NOT EXISTS `filter_has_nbar_protocol` (
  `filter_id` int(11) NOT NULL,
  `nbar_protocol_id` int(11) NOT NULL,
  PRIMARY KEY (`filter_id`,`nbar_protocol_id`),
  KEY `fk_filter_has_nbar_protocol_nbar_protocol1_idx` (`nbar_protocol_id`),
  KEY `fk_filter_has_nbar_protocol_filter1_idx` (`filter_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Vypisuji data pro tabulku `filter_has_nbar_protocol`
--

INSERT INTO `filter_has_nbar_protocol` (`filter_id`, `nbar_protocol_id`) VALUES
(1, 1),
(1, 2);

-- --------------------------------------------------------

--
-- Struktura tabulky `interface_list`
--

CREATE TABLE IF NOT EXISTS `interface_list` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `intf_name` varchar(100) DEFAULT NULL,
  `intf_type` varchar(100) DEFAULT NULL,
  `router_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_interface_list_router1_idx` (`router_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Struktura tabulky `ip_network`
--

CREATE TABLE IF NOT EXISTS `ip_network` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `address` varchar(45) DEFAULT NULL,
  `mask` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

--
-- Vypisuji data pro tabulku `ip_network`
--

INSERT INTO `ip_network` (`id`, `address`, `mask`) VALUES
(1, '192.168.1.100', 32),
(2, '192.168.1.200', 32);

-- --------------------------------------------------------

--
-- Struktura tabulky `nbar_protocol`
--

CREATE TABLE IF NOT EXISTS `nbar_protocol` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `protocol_name` varchar(45) DEFAULT NULL,
  `protocol_description` varchar(255) DEFAULT NULL,
  `protocol_id` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

--
-- Vypisuji data pro tabulku `nbar_protocol`
--

INSERT INTO `nbar_protocol` (`id`, `protocol_name`, `protocol_description`, `protocol_id`) VALUES
(1, 'SIP', 'SIP description', 'SIP'),
(2, 'HTTP', 'HTTP description', 'HTTP');

-- --------------------------------------------------------

--
-- Struktura tabulky `ports`
--

CREATE TABLE IF NOT EXISTS `ports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `greater_or_equal` int(11) DEFAULT NULL,
  `less_or_equal` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- Vypisuji data pro tabulku `ports`
--

INSERT INTO `ports` (`id`, `greater_or_equal`, `less_or_equal`) VALUES
(1, 0, 65535);

-- --------------------------------------------------------

--
-- Struktura tabulky `router`
--

CREATE TABLE IF NOT EXISTS `router` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `management_ip` varchar(45) DEFAULT NULL,
  `name` varchar(45) DEFAULT NULL,
  `application_id` int(11) NOT NULL,
  `username` varchar(45) DEFAULT NULL,
  `password` varchar(45) DEFAULT NULL,
  `interfaces` text,
  PRIMARY KEY (`id`),
  KEY `fk_router_application1_idx` (`application_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

--
-- Vypisuji data pro tabulku `router`
--

INSERT INTO `router` (`id`, `management_ip`, `name`, `application_id`, `username`, `password`, `interfaces`) VALUES
(1, '10.10.10.1', 'R1', 1, 'cisco', 'cisco', 'GigabitEthernet0/0'),
(2, '10.10.10.2', 'R2', 1, 'cisco2', 'cisco', 'GigabitEthernet0/1');

--
-- Omezení pro exportované tabulky
--

--
-- Omezení pro tabulku `access_list`
--
ALTER TABLE `access_list`
  ADD CONSTRAINT `fk_access_list_filter1` FOREIGN KEY (`filter_id`) REFERENCES `filter` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_access_list_ip_networks` FOREIGN KEY (`ip_source`) REFERENCES `ip_network` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_access_list_ip_networks1` FOREIGN KEY (`ip_destination`) REFERENCES `ip_network` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_access_list_ports1` FOREIGN KEY (`ports_id`) REFERENCES `ports` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Omezení pro tabulku `application`
--
ALTER TABLE `application`
  ADD CONSTRAINT `fk_application_analyzer1` FOREIGN KEY (`analyzer_id`) REFERENCES `analyzer` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_application_certificates1` FOREIGN KEY (`certificate_id`) REFERENCES `certificate` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Omezení pro tabulku `filter`
--
ALTER TABLE `filter`
  ADD CONSTRAINT `fk_policy_map_policy_map1` FOREIGN KEY (`application_id`) REFERENCES `application` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Omezení pro tabulku `filter_has_nbar_protocol`
--
ALTER TABLE `filter_has_nbar_protocol`
  ADD CONSTRAINT `fk_filter_has_nbar_protocol_filter1` FOREIGN KEY (`filter_id`) REFERENCES `filter` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_filter_has_nbar_protocol_nbar_protocol1` FOREIGN KEY (`nbar_protocol_id`) REFERENCES `nbar_protocol` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Omezení pro tabulku `interface_list`
--
ALTER TABLE `interface_list`
  ADD CONSTRAINT `fk_interface_list_router1` FOREIGN KEY (`router_id`) REFERENCES `router` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Omezení pro tabulku `router`
--
ALTER TABLE `router`
  ADD CONSTRAINT `fk_router_application1` FOREIGN KEY (`application_id`) REFERENCES `application` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
