
rule k2321_292d1123d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.292d1123d9eb1912"
     cluster="k2321.292d1123d9eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['53b838cec87cd047602b6e03a32d9bf2','59a12476fb25b9dd13966c66d4eb69b0','fca437ecd8d108e3ec9880c7435a7fdd']"

   strings:
      $hex_string = { 406c661d4c38035531f8d427de7aa6effaf6b381d8d3ebc0c3f2ce15983ffc7dfb450885507c8cbd093e8493885623f5dd77f878e70e4e39e46d89aea513232a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
