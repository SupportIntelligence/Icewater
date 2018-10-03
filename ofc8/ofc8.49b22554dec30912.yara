
rule ofc8_49b22554dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.49b22554dec30912"
     cluster="ofc8.49b22554dec30912"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['c059f5adc1523d39501fefdc2f88e4914fad061c','0aa2f3845340c6d3e2ca24ce5adb08dea84f40a1','a73cde897721c9e208109dd6b57c45b58dd6f0d7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.49b22554dec30912"

   strings:
      $hex_string = { 1fadf7314d78ce6ac6fa7acd4516d91c52f29c5ba527bc19bfb36f124975941b5d50406510a705081ea199000c2685368d0390d60972e8db86d33776bada4e02 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
