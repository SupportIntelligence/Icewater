
rule m3f7_2b9313b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b9313b9ca800b12"
     cluster="m3f7.2b9313b9ca800b12"
     cluster_size="10"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['03d18d2c0f43f6fb1d6942271ea02661','06255ca0b3cfd7fd229fa46cc2271724','e6c317966e0edb81dab127f8c7063886']"

   strings:
      $hex_string = { 783b206261636b67726f756e643a75726c28687474703a2f2f342e62702e626c6f6773706f742e636f6d2f2d62394f456d56644c3651342f5552415f424c374f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
