
rule k2319_691d8299c6200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.691d8299c6200932"
     cluster="k2319.691d8299c6200932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['57d35eac05ca72407ce65115d854162132febea1','d6e24a482053f320b56c0b9374e04c694aed21e1','7476d3f34123d686e953e609bc31d91bf4e2656f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.691d8299c6200932"

   strings:
      $hex_string = { 783144302c31302e39394532292929627265616b7d3b766172205a366d326a3d7b2778376a273a66756e6374696f6e284e2c55297b72657475726e204e7c553b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
