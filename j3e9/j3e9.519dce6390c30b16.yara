
rule j3e9_519dce6390c30b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.519dce6390c30b16"
     cluster="j3e9.519dce6390c30b16"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious buzus gnrx"
     md5_hashes="['18a6d58f6874ba311f261d7fd8be1c2e','32c5c6e2474ff4a16ded056809536af9','b9d666e0837f002b634f3b8956b4da1e']"

   strings:
      $hex_string = { 7586757bfe730582000004067276060301f6057a8b8507f47c7e740b7ff30db507c973890ef287fa017df373f777867a0c017087f10280f7f377fb7dfc0f05f4 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
