
rule k2321_091b8dbadbd30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.091b8dbadbd30912"
     cluster="k2321.091b8dbadbd30912"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi mofksys abzf"
     md5_hashes="['113e46d0ea1a0f27de3007f169148036','1c57993afcffcf6e2d4b2b6d24a5ece8','ffd9f6f656eb51f78bd9c8bd0d12b233']"

   strings:
      $hex_string = { db7f600cf2a6f8ca6fe72bbf5db86a931a41074dbbcfaa34a2ff23423c1d48d90ea0acdf8aefd4b6faf929b5c316dc59c7fb5f273672c28597d0799afe37ba3f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
