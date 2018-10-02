
rule nfc8_539ebab9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.539ebab9caa00b12"
     cluster="nfc8.539ebab9caa00b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos andr apbl"
     md5_hashes="['dd1ba1b036323454f8e346f274ae1e31b0dab00e','4fd1d318a31917bf7f36dc86a930794a04ca2e48','8f4fb869cd8fb49fa39d85a4025487ab67a214f7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.539ebab9caa00b12"

   strings:
      $hex_string = { eac7f8777de3a75fa2f3eb839c73882f9461a1f934e47b3be55156474f78369d71ffe731dfb38e63da59e62449abaf43d2ea6b44bd5407c6b7ec916a5c3ac899 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
