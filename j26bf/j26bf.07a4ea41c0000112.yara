
rule j26bf_07a4ea41c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.07a4ea41c0000112"
     cluster="j26bf.07a4ea41c0000112"
     cluster_size="59"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy tsklnk dotdo"
     md5_hashes="['8b4185aed4ff71b01377ddd4fc4870e199fa42c8','1516fcb6650646592d4a6ec7dcb7388840af669b','92d872bc9394f816e5c5a8e643f56402cd093eb7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.07a4ea41c0000112"

   strings:
      $hex_string = { 650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56697369626c65417474726962757465004775696441747472696275 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
