
rule k2319_5ad71ab9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5ad71ab9c8800912"
     cluster="k2319.5ad71ab9c8800912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['f435144bfbcb7c3b1df0750e06a3ae5233c7944a','18deb50ff517865d07e790f96d953c37b3a282f4','72b7a46207f2f66169cc9ae98c0307eeb1981aa6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5ad71ab9c8800912"

   strings:
      $hex_string = { 3a283133382e323045312c32342e354531292929627265616b7d3b76617220443863363d7b27623347273a226a222c274633273a66756e6374696f6e284b2c65 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
