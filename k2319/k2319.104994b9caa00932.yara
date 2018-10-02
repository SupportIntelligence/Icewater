
rule k2319_104994b9caa00932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.104994b9caa00932"
     cluster="k2319.104994b9caa00932"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c6546e2b84b02f51aafe1caabdc7e8509ffe6556','5fd31c5f8ce03f2a419a1ee07fabf9465efe39df','25d8e676b49143e99b3907105dfb652eff28bb3c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.104994b9caa00932"

   strings:
      $hex_string = { 43293f226f223a283132302e2c332e3537304532292929627265616b7d3b76617220753953314b3d7b275a3156273a27272c2778314b273a66756e6374696f6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
