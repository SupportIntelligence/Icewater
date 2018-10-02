
rule k2319_291196b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291196b9c8800b32"
     cluster="k2319.291196b9c8800b32"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a7962e0a0865e30fb9164091022f63ef09246669','921a5e9ae304deb08466f5da52261f0458e993fb','1c9481998acffebe31fe6cf075a5847c4b41f640']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291196b9c8800b32"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20785b6b5d3b7d76617220513d2833392e3c2839312e2c30784238293f283132362c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
