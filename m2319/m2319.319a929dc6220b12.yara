
rule m2319_319a929dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.319a929dc6220b12"
     cluster="m2319.319a929dc6220b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script html"
     md5_hashes="['b0f5c36eb09b973144d4e763b20cffffa1bb91bb','0989e0d0f1ee48415b28512f65f040e28ae7a629','ea5e096a970ab158a27d4bb4d1816862c7c1e8e3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.319a929dc6220b12"

   strings:
      $hex_string = { 7665727b6f7061636974793a332e393b7d0a2f2a2d2d53544152204d454e552057494e382d2d2a2f0a2e73616e74612d6d6172737b6261636b67726f756e643a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
