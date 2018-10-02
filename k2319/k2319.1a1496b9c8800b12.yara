
rule k2319_1a1496b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1496b9c8800b12"
     cluster="k2319.1a1496b9c8800b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c4c75d9ad8c49f7b65456e47b76b9fffbde6c9fb','cae28c72cd5a25ba7d8da6434a1420ae814e1df0','3373620b266b223ccf6f12dd6af2ced5971e0db5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1496b9c8800b12"

   strings:
      $hex_string = { 515d213d3d756e646566696e6564297b72657475726e20545b515d3b7d766172206a3d2839333c3d2835362c3078313646293f283130352e2c30786363396532 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
