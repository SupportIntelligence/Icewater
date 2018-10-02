
rule n3f8_6d38c209c6200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6d38c209c6200b32"
     cluster="n3f8.6d38c209c6200b32"
     cluster_size="618"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos backdoor banker"
     md5_hashes="['898d9d1fbadb32c6b3d6e5097bf195835a93a358','f3e9b6b178808955349319a38c5e14da012935f8','860dcaa4cfd9931016b3c4410fc6afa90e383a27']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6d38c209c6200b32"

   strings:
      $hex_string = { 0040303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
