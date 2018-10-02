
rule k2319_1812f666d9227b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1812f666d9227b12"
     cluster="k2319.1812f666d9227b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script fffazo"
     md5_hashes="['4222dc3c8aff210d7c70454994df19429ced27d7','c306435c494f61e738c224adf95bd65ba2b8b135','a0f6b45c0cda55159c10ee7751592fbeda287bc1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1812f666d9227b12"

   strings:
      $hex_string = { 39293a2838372e2c3130302e292929627265616b7d3b7661722070377637583d7b27633442273a2261646445222c276b3958273a66756e6374696f6e286c2c41 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
