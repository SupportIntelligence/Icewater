
rule k2319_181a9eb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181a9eb9c8800b12"
     cluster="k2319.181a9eb9c8800b12"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem multiplug"
     md5_hashes="['5f5691e99c5c637601d10e7b767e26a8d70ccf0f','14ea9a778122c3673901d1e0918714edb2eae379','52c5440c095a574b7e05f2a39ea92f280016b81e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181a9eb9c8800b12"

   strings:
      $hex_string = { 646f773b666f7228766172207a346120696e205832673461297b6966287a34612e6c656e6774683d3d3d2828392e313945322c3078313336293c30783141423f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
