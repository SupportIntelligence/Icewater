
rule k3f9_091b8dba99a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.091b8dba99a30912"
     cluster="k3f9.091b8dba99a30912"
     cluster_size="7"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mofksys symmi abzf"
     md5_hashes="['05f3aa9396d6dfe0505d0fd4fb2035df','39bbf16514bee4044190a3324d75cfe9','fdf7f8967a8f3f123981cdefe21608ce']"

   strings:
      $hex_string = { db7f600cf2a6f8ca6fe72bbf5db86a931a41074dbbcfaa34a2ff23423c1d48d90ea0acdf8aefd4b6faf929b5c316dc59c7fb5f273672c28597d0799afe37ba3f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
