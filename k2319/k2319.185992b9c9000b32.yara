
rule k2319_185992b9c9000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185992b9c9000b32"
     cluster="k2319.185992b9c9000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['04beaf3ce4d6632fa4d8f2f73c964e54c18f7833','2dc34b1597f65d1e26b062933ff0c2ebf55448cb','787f28a61ad09813ccb2b2d361262dca412f10bc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185992b9c9000b32"

   strings:
      $hex_string = { 756e646566696e6564297b72657475726e20475b535d3b7d76617220423d2828312e343645322c30783136293c3d35333f2836382e3745312c30786363396532 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
