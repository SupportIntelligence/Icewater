
rule n26d4_1192bcc9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1192bcc9c8000932"
     cluster="n26d4.1192bcc9c8000932"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu malicious banker"
     md5_hashes="['4e8913b5dddfef2236d458df10b2dd258de1b1c3','430a2c0bf128ff42eb4f59f510818cfa59c4cde5','8b1d3362e4b01cae52c81fb5c58b8d29ae885a27']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1192bcc9c8000932"

   strings:
      $hex_string = { 08034710014f1089c789cac1e902fcf3a589d183e103f3a45f09db75c65b5f5ec38d4000558bec83c4f8538bd8b201a1e4854100e8ff39feff8945fc33c05568 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
