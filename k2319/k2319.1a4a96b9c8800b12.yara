
rule k2319_1a4a96b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a4a96b9c8800b12"
     cluster="k2319.1a4a96b9c8800b12"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c4bda502b9a8ebce511e7c7e80c899143a7fc45b','dca0c25c36ce15c9f76fb5bfda26600038333251','b96aabb025ebc93c70920eba075ae8a199b73139']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a4a96b9c8800b12"

   strings:
      $hex_string = { 5b795d213d3d756e646566696e6564297b72657475726e20545b795d3b7d76617220563d283131342e3e3d2839302c33392e293f28352e353445322c30786363 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
