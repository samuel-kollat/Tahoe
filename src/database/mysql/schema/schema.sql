-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Feb 13, 2015 at 01:18 PM
-- Server version: 5.5.38-0ubuntu0.14.04.1
-- PHP Version: 5.5.9-1ubuntu4.3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `tahoe`
--

-- --------------------------------------------------------

--
-- Table structure for table `access_list`
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
  `pn_source` int(11) NOT NULL,
  `pn_destination` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_access_list_ip_networks_idx` (`ip_source`),
  KEY `fk_access_list_ip_networks1_idx` (`ip_destination`),
  KEY `fk_access_list_filter1_idx` (`filter_id`),
  KEY `fk_access_list_ports1_idx` (`pn_source`),
  KEY `fk_access_list_ports2_idx` (`pn_destination`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=4 ;

-- --------------------------------------------------------

--
-- Table structure for table `analyzer`
--

CREATE TABLE IF NOT EXISTS `analyzer` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) DEFAULT NULL,
  `description` varchar(45) DEFAULT NULL,
  `src` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

-- --------------------------------------------------------

--
-- Table structure for table `application`
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
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

-- --------------------------------------------------------

--
-- Table structure for table `certificate`
--

CREATE TABLE IF NOT EXISTS `certificate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) DEFAULT NULL,
  `root_cert_path` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

-- --------------------------------------------------------

--
-- Table structure for table `filter`
--

CREATE TABLE IF NOT EXISTS `filter` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) DEFAULT NULL,
  `type` varchar(45) DEFAULT NULL,
  `application_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_policy_map_policy_map1_idx` (`application_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=4 ;

-- --------------------------------------------------------

--
-- Table structure for table `filter_has_nbar_protocol`
--

CREATE TABLE IF NOT EXISTS `filter_has_nbar_protocol` (
  `filter_id` int(11) NOT NULL,
  `nbar_protocol_id` int(11) NOT NULL,
  PRIMARY KEY (`filter_id`,`nbar_protocol_id`),
  KEY `fk_filter_has_nbar_protocol_nbar_protocol1_idx` (`nbar_protocol_id`),
  KEY `fk_filter_has_nbar_protocol_filter1_idx` (`filter_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `interface_list`
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
-- Table structure for table `ip_network`
--

CREATE TABLE IF NOT EXISTS `ip_network` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `address` varchar(45) DEFAULT NULL,
  `mask` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

-- --------------------------------------------------------

--
-- Table structure for table `nbar_protocol`
--

CREATE TABLE IF NOT EXISTS `nbar_protocol` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `protocol_name` varchar(45) DEFAULT NULL,
  `protocol_description` varchar(255) DEFAULT NULL,
  `protocol_id` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=6 ;

-- --------------------------------------------------------

--
-- Table structure for table `ports`
--

CREATE TABLE IF NOT EXISTS `ports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `greater_or_equal` int(11) DEFAULT NULL,
  `less_or_equal` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=4 ;

-- --------------------------------------------------------

--
-- Table structure for table `router`
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
-- Constraints for dumped tables
--

--
-- Constraints for table `access_list`
--
ALTER TABLE `access_list`
  ADD CONSTRAINT `fk_access_list_filter1` FOREIGN KEY (`filter_id`) REFERENCES `filter` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_access_list_ip_networks` FOREIGN KEY (`ip_source`) REFERENCES `ip_network` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_access_list_ip_networks1` FOREIGN KEY (`ip_destination`) REFERENCES `ip_network` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_access_list_ports1` FOREIGN KEY (`pn_source`) REFERENCES `ports` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_access_list_ports2` FOREIGN KEY (`pn_destination`) REFERENCES `ports` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Constraints for table `application`
--
ALTER TABLE `application`
  ADD CONSTRAINT `fk_application_analyzer1` FOREIGN KEY (`analyzer_id`) REFERENCES `analyzer` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_application_certificates1` FOREIGN KEY (`certificate_id`) REFERENCES `certificate` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Constraints for table `filter`
--
ALTER TABLE `filter`
  ADD CONSTRAINT `fk_policy_map_policy_map1` FOREIGN KEY (`application_id`) REFERENCES `application` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Constraints for table `filter_has_nbar_protocol`
--
ALTER TABLE `filter_has_nbar_protocol`
  ADD CONSTRAINT `fk_filter_has_nbar_protocol_filter1` FOREIGN KEY (`filter_id`) REFERENCES `filter` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_filter_has_nbar_protocol_nbar_protocol1` FOREIGN KEY (`nbar_protocol_id`) REFERENCES `nbar_protocol` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Constraints for table `interface_list`
--
ALTER TABLE `interface_list`
  ADD CONSTRAINT `fk_interface_list_router1` FOREIGN KEY (`router_id`) REFERENCES `router` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Constraints for table `router`
--
ALTER TABLE `router`
  ADD CONSTRAINT `fk_router_application1` FOREIGN KEY (`application_id`) REFERENCES `application` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
