
rule m2319_299e93a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.299e93a9c8000b32"
     cluster="m2319.299e93a9c8000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector script html"
     md5_hashes="['9c33cd32407f0bfdc0b4895db64e2d43590fad1b','01ebde1e7bb7bf5eb8f6be8725560d5b81ff5ded','37f3d52d2a115f041b5a5103b711f573ac0a0717']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.299e93a9c8000b32"

   strings:
      $hex_string = { 3163662d393642382d343434353533353430303030227d2c686173446174613a66756e6374696f6e2865297b72657475726e20653d652e6e6f6465547970653f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
