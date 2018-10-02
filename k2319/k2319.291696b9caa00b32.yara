
rule k2319_291696b9caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291696b9caa00b32"
     cluster="k2319.291696b9caa00b32"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ac5f5f278fc5f7b8543c39b8bbaf5518b01ff082','30373bad987809270c1103ff1466a1c0a8a2d084','580c4167738f0cc0116aeb58906c5b0c76e85fb0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291696b9caa00b32"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e206e5b725d3b7d76617220493d2828307838332c352e354532293c32382e3645313f2834342c226a22293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
