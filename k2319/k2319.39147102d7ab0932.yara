
rule k2319_39147102d7ab0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39147102d7ab0932"
     cluster="k2319.39147102d7ab0932"
     cluster_size="187"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script flooder loic"
     md5_hashes="['285b046abc1e1e1e979d6b90333105553fe27826','a25f320064f0b27e6e4f6405441825f7ebf590b9','d2850bc3cdcdd3fd6e536221d729859b1a3a3e61']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39147102d7ab0932"

   strings:
      $hex_string = { 2e636f6d2f696d616765733f713d74626e3a414e643947635467303977335932784858537645624774776332664f3435537538366a5a48692d75625033705155 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
