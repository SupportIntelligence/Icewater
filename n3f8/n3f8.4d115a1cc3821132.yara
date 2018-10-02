
rule n3f8_4d115a1cc3821132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.4d115a1cc3821132"
     cluster="n3f8.4d115a1cc3821132"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos dldr ehco"
     md5_hashes="['20def3c99788c0fe609271006a8a5d08e8a97793','7f75109bd3c3add1b57d3a6bc588b6d0b857b3a8','9f2500fc6e24fb1676100dbeeda47c0e700069ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.4d115a1cc3821132"

   strings:
      $hex_string = { 4d6574686f643c54543b3e3b002f4c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f506c6174666f726d24416e64726f69643b00404c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
