
rule m2319_372d49e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.372d49e9c8800b32"
     cluster="m2319.372d49e9c8800b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery html script"
     md5_hashes="['2853c0c9cebde77dac4e4cc459c1c57e93da1ce0','230528423f2ce034265e2cc2778fbf763dcdd1d1','71a76552dc109aa1caf5cea44e76218972658a78']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.372d49e9c8800b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
