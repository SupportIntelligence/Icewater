
rule k2319_29349eb9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29349eb9c8800932"
     cluster="k2319.29349eb9c8800932"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['2de79bc39f7a8c017a92d1c3dddfb14ae78e49dc','16400c8894ca020765477dc0a1d960cf30f25f9d','0641aeceb3ed5906ab772bb73fdeb1d0e81b76f9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29349eb9c8800932"

   strings:
      $hex_string = { 2831362c3078313443292929627265616b7d3b76617220663248303d7b274a3969273a2268222c27663350273a322c274330273a66756e6374696f6e28532c70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
