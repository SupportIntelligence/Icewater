
rule k26d4_13a96926df193912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d4.13a96926df193912"
     cluster="k26d4.13a96926df193912"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="midie ardamax keylogger"
     md5_hashes="['6ba8d63c2718c974afee0af117df1864e63f8949','8d90c52484ee446b27a6c002b62adbe0a4976096','d1d30258392750860d12d33ce2bef7f83cb83a27']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d4.13a96926df193912"

   strings:
      $hex_string = { be4fe640bbeb0b85f375078bc6c1e0100bf0893520d30001f7d6893524d300015e5f5bc9c38bff558bec8b450833c93b04cd88d0000174134183f92d72f18d48 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
