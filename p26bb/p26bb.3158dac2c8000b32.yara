
rule p26bb_3158dac2c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.3158dac2c8000b32"
     cluster="p26bb.3158dac2c8000b32"
     cluster_size="2879"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dropped crypt genericr"
     md5_hashes="['c1f11e32d2fe00e2f757cd98affc69de326e4879','2fd773753a801d3f77e1aa88b8820a0086f098af','f354ab93e2412763a8572866582c93ed28adb3d8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.3158dac2c8000b32"

   strings:
      $hex_string = { ea26fd449dc8ac52e8255e80ecf8818833431a40dceb34cf18f611b83895fbab281776c6d4d042125f1bb0dae03e105df7f37a29547bc013048d477c2b2d837f }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
