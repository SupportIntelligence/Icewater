
rule n26bb_219a55c9c6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.219a55c9c6620b32"
     cluster="n26bb.219a55c9c6620b32"
     cluster_size="53"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bunitu trojanproxy bscope"
     md5_hashes="['c8e5a0af44cab2a14fd9bbfd609b4785b16cb168','304a771c7279e82db7411914e3b776745071f010','3c26219be8026ea349ffd7e0ac42f0f651bf26dd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.219a55c9c6620b32"

   strings:
      $hex_string = { 23ff343434ff505151ff646667ff59595bff000000ff000000ff4f5160ff515261ff3c3d48ff2c2d35ff1f2026ff1d1d22ff1a1c21ff18191dff16171bff1415 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
