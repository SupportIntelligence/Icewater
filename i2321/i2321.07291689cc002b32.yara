
rule i2321_07291689cc002b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.07291689cc002b32"
     cluster="i2321.07291689cc002b32"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['2d3afe4c6e2934c854c17a18658b97cf','2d5f61924310c901cb5ec319714ce656','b568f06f3cc009c9cbb8caed5cc0e6f1']"

   strings:
      $hex_string = { c65a7b43fa5efbe9c0dd3df96dccef89a7e1e54db1c1b8e66d31f6daa6d8c1183b10639736c56a83edf7e82b9b62df8eb142fec3dfff03a1586e560f9f3f5fa9 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
