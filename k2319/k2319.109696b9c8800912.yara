
rule k2319_109696b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.109696b9c8800912"
     cluster="k2319.109696b9c8800912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a779c983f99fb0513ab96117fa665b1205f57469','80b57d7deb56096272358b45cbe6181d253fd28c','22e5f08489f3e907220dc9bb0b3e73bee3043867']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.109696b9c8800912"

   strings:
      $hex_string = { 66696e6564297b72657475726e20415b565d3b7d766172206f3d2828307831392c37382e293c34362e3745313f28372e3245322c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
