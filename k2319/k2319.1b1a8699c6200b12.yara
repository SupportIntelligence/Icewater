
rule k2319_1b1a8699c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1b1a8699c6200b12"
     cluster="k2319.1b1a8699c6200b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem multiplug"
     md5_hashes="['354c0c5adeafbadb040ecd994ee237b93b29b29a','5c8f934c5949268998afa863ac255e563c5160a0','52c974522da06357c7b9f8ab5821213c4b6430da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1b1a8699c6200b12"

   strings:
      $hex_string = { 373a2832342e2c33382e38304531292929627265616b7d3b7661722068394a304d3d7b277a3061273a226e74222c2765354d273a66756e6374696f6e284f2c56 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
