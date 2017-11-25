
rule m2377_2b9b13b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b9b13b9caa00b12"
     cluster="m2377.2b9b13b9caa00b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script clicker"
     md5_hashes="['2d57d50d1d93db3a2b3e573cc5a9c818','71b817fa6d52106ff10286fcfcca78e8','bf8a895a7f9a641ec826f426a6fea064']"

   strings:
      $hex_string = { 28293b0a696d67725b305d203d2022687474703a2f2f322e62702e626c6f6773706f742e636f6d2f2d7569745837524f507454552f5479762d47344e415f7549 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
