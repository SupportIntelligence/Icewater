
rule m2319_639896c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.639896c9c8000b12"
     cluster="m2319.639896c9c8000b12"
     cluster_size="14"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack clicker"
     md5_hashes="['01e4d57d0e01ec1e3b2c88c8f0a4cf47','31d87a28820c7edb40f2aec6bb42a657','ea0726ba0d8e37d38553f498adee9fc1']"

   strings:
      $hex_string = { 722e636f6d2f7265617272616e67653f626c6f6749443d3638373231373038313637313339353634393826776964676574547970653d426c6f67417263686976 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
