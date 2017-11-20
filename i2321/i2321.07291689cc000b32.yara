
rule i2321_07291689cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.07291689cc000b32"
     cluster="i2321.07291689cc000b32"
     cluster_size="18"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['22367dc2e5797a8b881c0377a9e1f031','2c3f06f222f71e6dc34f3baf9cc847e8','e3af673501a5b733f1bc1dd12308da35']"

   strings:
      $hex_string = { c65a7b43fa5efbe9c0dd3df96dccef89a7e1e54db1c1b8e66d31f6daa6d8c1183b10639736c56a83edf7e82b9b62df8eb142fec3dfff03a1586e560f9f3f5fa9 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
