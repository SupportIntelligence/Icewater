
rule n231d_091c9699c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.091c9699c2200b32"
     cluster="n231d.091c9699c2200b32"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hqwar bankbot"
     md5_hashes="['c55cd3ef90c25fbf3bd39a593016918e32c3d627','f252ff0ce5cba95fe0811bf38a8c23f5cb3b2bb6','25c3e0a96387b0fc9ca71e20de385ed438656620']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.091c9699c2200b32"

   strings:
      $hex_string = { 9c311c18ac6762a49d9bab3f3661d3660b2297bb5f5541a880cb69d1c21b89fb300f744c13393e4a4934fd45d0d803b5eabce705fe9a5683ddd20251aa96b6f7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
