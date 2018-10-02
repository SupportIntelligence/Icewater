
rule k2319_501296b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.501296b9caa00b12"
     cluster="k2319.501296b9caa00b12"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5cde89c693096f4e08f37cae30fe2957c46be802','2dc6ae7ed3baacea35dae6a5d0e87b9fc02d36e1','e6d8f1ce09cc6de5e3a206d32410f7a4a4a2450a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.501296b9caa00b12"

   strings:
      $hex_string = { 3c392e313645323f28372c313139293a2831372c3078313646292929627265616b7d3b7661722042315130763d7b27453076273a66756e6374696f6e284b2c47 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
