
rule k2319_791696a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.791696a9c8800b12"
     cluster="k2319.791696a9c8800b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5b2592563cfdb35dd43aa26c7a24005606834aeb','1b61ac80ce45310c9dfe16b2d875871689dad053','206ed9eb72f18a89d3176a2e45933614867e8cd5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.791696a9c8800b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e20745b5a5d3b7d76617220643d2828372e393445322c313338293e3d34313f2832362e393045312c30786363 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
