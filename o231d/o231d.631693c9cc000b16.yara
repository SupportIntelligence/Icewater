
rule o231d_631693c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.631693c9cc000b16"
     cluster="o231d.631693c9cc000b16"
     cluster_size="103"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp riskware clicker"
     md5_hashes="['2b79fc3286f71c18c0f9a1b85f4801b68a27d320','434a3e0b529355d49ab85a93e65655b5fa8d1f23','7b8dde987180a31416f12d157c1a58a55bf32f41']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.631693c9cc000b16"

   strings:
      $hex_string = { 87c3985227920903a9cac8de940266140d62403bc9fc8c56ac883906431a216711610770af4e6ec45e3d81f72c689bfdeef0faa70fd9f1eab3a7497ae2ba5459 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
