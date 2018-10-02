
rule n26bb_219855c9c6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.219855c9c6620b32"
     cluster="n26bb.219855c9c6620b32"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bunitu trojanproxy bscope"
     md5_hashes="['79e074c5d5367b096be24782b16e3ddaad839af3','bfaf3200ce3f32b56148a5da3afa867bb5efc264','94d12382dd5d69e66ae9ae5cdcd956bf616e40d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.219855c9c6620b32"

   strings:
      $hex_string = { 5274af5238d4cb2a0065932c6b56b2443067bd3e387cfe3d4d6d8b3c532ea6286c6dbb3a4b379747501cad4a4816b0f855b4896c75bc8f3c650e956c6f1db55d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
