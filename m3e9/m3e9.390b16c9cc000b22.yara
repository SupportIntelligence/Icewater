
rule m3e9_390b16c9cc000b22
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.390b16c9cc000b22"
     cluster="m3e9.390b16c9cc000b22"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shodi prepender virut"
     md5_hashes="['1030636dcd1e1b480c7130fbb4dd5973','3c1754bf9aad033c7f8e11b09cb8795e','b4559b07a3db77d3f62c11f63bc49dbb']"

   strings:
      $hex_string = { 8a084084c975f92bc28bf083fe048bfe730433c0eb3e6a0b687c32000153ff155012000183c40c85c075058d46f6eb2485f67409803c1f5c74034f75f7b87cbd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
