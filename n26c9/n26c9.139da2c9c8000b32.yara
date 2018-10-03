
rule n26c9_139da2c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c9.139da2c9c8000b32"
     cluster="n26c9.139da2c9c8000b32"
     cluster_size="854"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="runbooster malicious badfile"
     md5_hashes="['c468009ce05e91d395a18e1a4dcaf85198e8acee','d3d7c10b8e261523488bdc732a1b2fda577ca926','e1de2e9e85bc2495d5cfed8acc990a11faab52d6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c9.139da2c9c8000b32"

   strings:
      $hex_string = { 83c2024983e801eb0f41b801000000663908450f42c4eb0575d9458bc74585c075074d3bd172027619033b3b7b0c0f82eafeffff488b5b184885db7409e9ccfe }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
