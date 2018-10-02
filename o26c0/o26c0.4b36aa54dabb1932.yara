
rule o26c0_4b36aa54dabb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.4b36aa54dabb1932"
     cluster="o26c0.4b36aa54dabb1932"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor dlassistant heuristic"
     md5_hashes="['1fe27f2db44a5e9fe6d55b41fcfcf92c1f849dad','a9756dfd871ea122563294a2096aa82715db6cd4','90a9bde2b5c81fd3647530b7155f87a6ac93fd5e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.4b36aa54dabb1932"

   strings:
      $hex_string = { e8949524f5b6c21954096f90caf6bb32d4c107a1af52118b4d23876ef1edd8bd4fc36688ad730f8427e7461f64d3cb9efa7e0b263ab71a75f7dedb1b683f2cbe }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
