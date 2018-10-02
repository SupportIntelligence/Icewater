
rule j26bf_07a46a01c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.07a46a01c0000112"
     cluster="j26bf.07a46a01c0000112"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy tsklnk dotdo"
     md5_hashes="['bc63edbd73167ebe9d39ecf9a9ad26a68d499fa6','33fb17c43c12757b6be321a19337d3e20f3f12f7','936d670a05f98bc7de74a891eccab8e5ba05d0e4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.07a46a01c0000112"

   strings:
      $hex_string = { 650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56697369626c65417474726962757465004775696441747472696275 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
