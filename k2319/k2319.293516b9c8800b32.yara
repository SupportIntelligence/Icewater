
rule k2319_293516b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.293516b9c8800b32"
     cluster="k2319.293516b9c8800b32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik mplug script"
     md5_hashes="['4ed5f2968a9165b61bfe21c7ea5cdc29cd5207f1','3a0e5ce23b5b500eaf14b68f276c3a14b34c0ccc','14dc9eb43ee4866bbbf6ef6752b07bafa9bb5618']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.293516b9c8800b32"

   strings:
      $hex_string = { 3139293a28307843432c3433292929627265616b7d3b7661722078327630733d7b27683278273a227379222c27713373273a66756e6374696f6e28422c4f2c4a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
