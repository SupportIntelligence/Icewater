
rule ofc8_5b1a82d0d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.5b1a82d0d6c30912"
     cluster="ofc8.5b1a82d0d6c30912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos rootnik shuame"
     md5_hashes="['2ccabc8d644198aa4d56f37c3de78fa2a0453c4f','312c6b3367d2d173e8bcca8bb1344a58b644ce4a','821f9b05e96c845dda3d45ab8b5ee77f5f9cd8c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.5b1a82d0d6c30912"

   strings:
      $hex_string = { 8346bae1d56f82c1619a8545f3668ae854b7db0f96c7f572c2fd53aa885b27eee7a9e2df7f2d017bd1301ac4f0957a8f87ed269da24302b07e74fcc35a8494ce }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
