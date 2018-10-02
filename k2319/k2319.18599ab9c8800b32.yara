
rule k2319_18599ab9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18599ab9c8800b32"
     cluster="k2319.18599ab9c8800b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['f546f1b64a84bf6f39279ca064d88cea230aed65','05ef8742509ef29874d25b042cebba2ac04543df','96706f0ef6aaf012217efaeaf31babd4cc4b7365']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18599ab9c8800b32"

   strings:
      $hex_string = { 756e646566696e6564297b72657475726e20475b535d3b7d76617220423d2828312e343645322c30783136293c3d35333f2836382e3745312c30786363396532 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
