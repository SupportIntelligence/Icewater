
rule n2319_29142144dd02f111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.29142144dd02f111"
     cluster="n2319.29142144dd02f111"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery classic dldr"
     md5_hashes="['2294aca54e190cfc489027fae866477c988234c4','caa7b8af056c2570dfdbab07c5939c13dd75d791','040f286bd09209b17f1f549543db93e88fa81ac8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.29142144dd02f111"

   strings:
      $hex_string = { 7828302c206a5175657279282723777061646d696e62617227292e6865696768742829293b0a0a0969662028414e434f52415f474c4f42414c535b27746f705f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
