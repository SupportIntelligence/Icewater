
rule n3e9_1b1d3949c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1d3949c8000b32"
     cluster="n3e9.1b1d3949c8000b32"
     cluster_size="1562"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0001d1742ae9df40f0d0e6665d6849dd','00174ff28ea66ac2d52a453bac69525a','041c3415f93cde692f9e102f35b38c92']"

   strings:
      $hex_string = { b2773e9a583183b2d877db6293b7eba82ea4b8b3b99fbf3a66fecacfc2ac10a44cad861588121c315a2de045a67c19458d01461bd4eb7b2eac43b4bb6e6e65b8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
