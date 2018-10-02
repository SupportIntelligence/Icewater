
rule k2319_181ad4b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181ad4b9ca800b12"
     cluster="k2319.181ad4b9ca800b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem expkit"
     md5_hashes="['3d724960d73dd434c0474778a6d5286cd6e48680','40a5cd1aa160c85cbb58f07586cbec9727b004b9','67c2566c69a8efe7d806b7f4ea769c9201924070']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181ad4b9ca800b12"

   strings:
      $hex_string = { 35313045333a28392e3845322c322e32374532292929627265616b7d3b7661722073385338383d7b27473642273a6e756c6c2c27413838273a66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
