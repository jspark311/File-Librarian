CREATE DATABASE  IF NOT EXISTS `datahive_versions` /*!40100 DEFAULT CHARACTER SET utf8 */;
USE `datahive_versions`;

--
-- Table structure for table `db_version`
--

DROP TABLE IF EXISTS `db_version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `db_version` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `version` int(10) unsigned NOT NULL,
  `datetime_created` datetime NOT NULL DEFAULT current_timestamp(),
  `log` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `version_UNIQUE` (`version`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

INSERT INTO `db_version` (`id`, `version`, `datetime_created`, `log`) VALUES
(1, 1, '2018-10-11 05:40:19', 'Initial version.');

--
-- Table structure for table `file_meta`
--

DROP TABLE IF EXISTS `file_meta`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `file_meta` (
  `id` int(12) unsigned NOT NULL AUTO_INCREMENT,
  `id_dh_snapshot` int(10) unsigned DEFAULT NULL COMMENT 'This is the ID of the snapshot of the data.',
  `datetime_created` datetime NOT NULL DEFAULT current_timestamp(),
  `ctime` datetime NOT NULL,
  `mtime` datetime NOT NULL,
  `size` BIGINT unsigned NOT NULL,
  `userflags` int(10) unsigned DEFAULT 0,
  `isdir` tinyint(1) NOT NULL,
  `isfile` tinyint(1) NOT NULL,
  `islink` tinyint(1) NOT NULL,
  `examined` tinyint(1) NOT NULL,
  `rel_path` mediumblob NOT NULL COMMENT 'The relative path of this file from the root of the datahive.',
  `sha256` varchar(64) NOT NULL,
  `owner` varchar(48) NOT NULL,
  `group` varchar(48) NOT NULL,
  `perms` varchar(12) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 CHECKSUM=1;

--
-- Table structure for table `file_meta`
--

DROP TABLE IF EXISTS `datahive_version`;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `datahive_version` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `datetime_created` datetime NOT NULL DEFAULT current_timestamp(),
  `tag` varchar(64) NOT NULL,
  `count_files` int(12) unsigned NOT NULL,
  `count_links` int(12) unsigned NOT NULL,
  `count_directories` int(12) unsigned NOT NULL,
  `rel_path` mediumblob NOT NULL COMMENT 'The relative path of the root of the datahive.',
  `notes` blob NOT NULL COMMENT 'Optional notes surrounding this catalog.',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 CHECKSUM=1;

/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-11-05 15:24:44
