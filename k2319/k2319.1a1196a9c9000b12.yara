
rule k2319_1a1196a9c9000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1196a9c9000b12"
     cluster="k2319.1a1196a9c9000b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['8d9cc8a14ee55183473b2d0f1a245fec7cebcd15','57fa7e87d01c045f0a08adb6b926a567d3bac3b9','c36eb1c8e7af2eab01cd85c5611bf9c07156ffc9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1196a9c9000b12"

   strings:
      $hex_string = { 5b565d213d3d756e646566696e6564297b72657475726e204f5b565d3b7d766172207a3d28392e3545323e28312e3031373045332c37362e354531293f283634 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
