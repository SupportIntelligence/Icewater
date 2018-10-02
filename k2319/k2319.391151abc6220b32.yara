
rule k2319_391151abc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391151abc6220b32"
     cluster="k2319.391151abc6220b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['4b021f7f91667cb6fc04424e79987aa96d104213','0749f426af5fae86e8e2b38501c151e320fe83ee','3bab33be3db0ec8f0e8083fe3912996eabae32fb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391151abc6220b32"

   strings:
      $hex_string = { 28307837342c3130382e292929627265616b7d3b76617220743954313d7b274939273a66756e6374696f6e28482c53297b72657475726e20482d533b7d2c2752 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
