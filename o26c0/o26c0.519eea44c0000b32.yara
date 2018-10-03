
rule o26c0_519eea44c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.519eea44c0000b32"
     cluster="o26c0.519eea44c0000b32"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="strictor malicious dangerousobject"
     md5_hashes="['b2d97291eae4836e5c872493ed9d9a4bfdfc73b5','f8cb60f357ecccfc64ec439fb5d2b19ed7601f53','5ae2d188749498bf4660d38e18e4deb0efe48bd8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.519eea44c0000b32"

   strings:
      $hex_string = { c26a2083e01f592bc8d3cf33fa873b33c05f5e5b5dc38bff558bec8b4508578d3c85b0b55c008b0f85c9740b8d4101f7d81bc023c1eb57538b1c85d8dc400056 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
