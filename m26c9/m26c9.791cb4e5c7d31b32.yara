
rule m26c9_791cb4e5c7d31b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c9.791cb4e5c7d31b32"
     cluster="m26c9.791cb4e5c7d31b32"
     cluster_size="3080"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="runbooster malicious heuristic"
     md5_hashes="['dfef1872f99c8a6f50cdb6718977e72ec7268322','a22bcf4c27ce5dba4b68e153569d8fb659fd9ad0','bb55d36b290532ac58ecd4e40800acd0a294c145']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c9.791cb4e5c7d31b32"

   strings:
      $hex_string = { fb41740d8d43bb83f80276054532f6eb0341b601488bbc24c800000040f6c708752ae83df5ffff85c07421498b174c8bcd48c1ea3f4c8bc680e2014488742420 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
