
rule i26e2_1d2b1299c6001122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26e2.1d2b1299c6001122"
     cluster="i26e2.1d2b1299c6001122"
     cluster_size="97"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dorkbot winlnk dobex"
     md5_hashes="['0ee69b47425dc9dfe4ac248d84590471f13a28e5','b7e024600c77040cfc958ebe0549c8e8f7ff3238','37b49429250ee5ce701b3b5bdb231370131a5a07']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26e2.1d2b1299c6001122"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c00000000000000000000000000000000000000520031000000000000000000100077696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
