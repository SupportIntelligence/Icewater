
rule n231d_09189699c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.09189699c2200b32"
     cluster="n231d.09189699c2200b32"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker hqwar"
     md5_hashes="['e4f36c08efbcec888600c6482407944ba887e766','d569098ec85bc39333af2866b0c50298c6aa40b1','8912a5d7334cb328c4f4e9e64b8f4c189a8742fc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.09189699c2200b32"

   strings:
      $hex_string = { 9c311c18ac6762a49d9bab3f3661d3660b2297bb5f5541a880cb69d1c21b89fb300f744c13393e4a4934fd45d0d803b5eabce705fe9a5683ddd20251aa96b6f7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
