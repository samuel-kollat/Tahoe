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

--
-- Dumping data for table `access_list`
--

INSERT INTO `access_list` (`id`, `number`, `action`, `protocol`, `ip_source`, `ip_destination`, `ttl`, `filter_id`, `pn_source`, `pn_destination`) VALUES
(3, NULL, 'permit', 'TCP,UDP', 1, 2, NULL, 1, 1, 0);

--
-- Dumping data for table `analyzer`
--

INSERT INTO `analyzer` (`id`, `name`, `description`, `src`) VALUES
(1, 'VoIP', 'Analyzer for VoIP', '/var/analyzer/voip.c'),
(2, 'HTTP', 'Analyzer for HTTP', '/var/analyzer/http.c');

--
-- Dumping data for table `application`
--

INSERT INTO `application` (`id`, `name`, `active_flag`, `certificate_id`, `analyzer_id`) VALUES
(1, 'VoIP monitoring', NULL, 1, 1),
(2, 'HTTP monitoring', NULL, 1, 2);

--
-- Dumping data for table `certificate`
--

INSERT INTO `certificate` (`id`, `name`, `root_cert_path`) VALUES
(1, 'cert1', '/home/user/cert.pem');

--
-- Dumping data for table `filter`
--

INSERT INTO `filter` (`id`, `name`, `type`, `application_id`) VALUES
(1, 'filter1 - http', NULL, 2),
(3, 'filter2 - voip', NULL, 1);

--
-- Dumping data for table `filter_has_nbar_protocol`
--

INSERT INTO `filter_has_nbar_protocol` (`filter_id`, `nbar_protocol_id`) VALUES
(3, 1),
(1, 2),
(1, 3),
(3, 4),
(3, 5);

--
-- Dumping data for table `ip_network`
--

INSERT INTO `ip_network` (`id`, `address`, `mask`) VALUES
(1, '192.168.1.100', 32),
(2, '192.168.1.200', 32);

--
-- Dumping data for table `nbar_protocol`
--

INSERT INTO `nbar_protocol` (`id`, `protocol_name`, `protocol_description`, `protocol_id`) VALUES
(1, 'SIP', 'SIP description', 'SIP'),
(2, 'HTTP', 'HTTP description', 'HTTP'),
(3, 'DNS', 'DNS description', 'DNS'),
(4, 'RTP', 'RTP description', 'RTP'),
(5, 'RTCP', 'RTCP description', 'RTCP');

--
-- Dumping data for table `ports`
--

INSERT INTO `ports` (`id`, `greater_or_equal`, `less_or_equal`) VALUES
(0, 0, 65535),
(1, 80, 80),
(2, 53, 53),
(3, 443, 443);

--
-- Dumping data for table `router`
--

INSERT INTO `router` (`id`, `management_ip`, `name`, `application_id`, `username`, `password`, `interfaces`) VALUES
(1, '10.10.10.1', 'R1', 1, 'cisco', 'cisco', 'GigabitEthernet0/0'),
(2, '10.10.10.2', 'R2', 1, 'cisco2', 'cisco', 'GigabitEthernet0/1');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
