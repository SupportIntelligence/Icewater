
rule k2319_391d56b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391d56b9c8800b32"
     cluster="k2319.391d56b9c8800b32"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik asmalwsc crypt"
     md5_hashes="['ca01d28af04997a3b60fcf74282f90b2741d3a0e','f137f28a21b414906b372494f4bb945f63e7c510','b5cd33dc13d2e494d795472e0e6876273eb65b12']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391d56b9c8800b32"

   strings:
      $hex_string = { 2830783135452c312e324532292929627265616b7d3b766172204e3647363d7b274e356a273a2263686172222c277a34273a66756e6374696f6e286c2c55297b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
