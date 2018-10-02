
rule n3f8_5a06e44980000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.5a06e44980000110"
     cluster="n3f8.5a06e44980000110"
     cluster_size="53"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker piom"
     md5_hashes="['c413b80aa108a819ca1aa7000f78b05ffa11a01a','d22ed2ec71153d6ee4529072b26080811e830b94','ebb2f608c60fb95ba70b81f8e472d465738d14ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.5a06e44980000110"

   strings:
      $hex_string = { 313b00364c636f6d2f73717561726575702f686168612f67756176612f636f6c6c6563742f4d61707324456e74727946756e6374696f6e24323b00344c636f6d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
