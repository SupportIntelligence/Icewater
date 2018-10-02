
rule k2319_181296e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181296e9c8800b12"
     cluster="k2319.181296e9c8800b12"
     cluster_size="64"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['1c650ce938eabeec58b1f67e16bc0cd83a264dba','a243d8702dc6d06fc4a3bce7f4c76cdd05786a6e','87ebc61304adabbbb6f2142ee6a05292da2815db']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181296e9c8800b12"

   strings:
      $hex_string = { 7845352c3130302e292929627265616b7d3b766172205532733d7b27473444273a22637265222c27523944273a2261222c274c36273a66756e6374696f6e2854 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
