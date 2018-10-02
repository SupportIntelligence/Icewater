
rule o3f8_69b052bad4bb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f8.69b052bad4bb1112"
     cluster="o3f8.69b052bad4bb1112"
     cluster_size="99"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clicker androidos apprisk"
     md5_hashes="['9529254eaac41ed0865864c0a4f6e3aba5a91b3b','fc9a2d49a04105dfb3193cb0fb4454b29f3dd410','93f6da3eb0d9a6263882c58ad9c0763906466bc5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o3f8.69b052bad4bb1112"

   strings:
      $hex_string = { 8e22527346005274470070407a002143071028e10d015472440022032c00527446005275470070407a0063546e10585c01000c0171209b0013000c017220e25e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
