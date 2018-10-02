
rule k2319_381683afc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.381683afc6220b12"
     cluster="k2319.381683afc6220b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['119d378a68fdf2417ccee102e77158469e5e6782','4777c1d68c6205a0775301d9d4482ac245fba80c','7e01cae28b9d016d36ed12975a57f450c7bf6f88']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.381683afc6220b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20755b525d3b7d76617220533d28283078382c31312e293c3d2831332e383845322c37352e293f28362e2c3078636339653264 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
