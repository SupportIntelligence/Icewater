
rule n3f7_2b9993c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.2b9993c9c4000b12"
     cluster="n3f7.2b9993c9c4000b12"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack clicker clickjack"
     md5_hashes="['07a852a413d9e13b8911bd4935ceb56b','2d025a1afeda1235b9c8d089ccba1bcd','d2e48bc99d3ca23ddd2bd1910445e84c']"

   strings:
      $hex_string = { 2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e746573 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
