
rule m2319_4394e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4394e448c0000b12"
     cluster="m2319.4394e448c0000b12"
     cluster_size="42"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker clicker"
     md5_hashes="['4595904093fe9bbe08db4c144ff11d3a1399999f','75805ef73cd6d186d0e3f88a5c91eb81a923afe7','69dc3d70e32961b2a3abb63e3ed3c8797b21b862']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.4394e448c0000b12"

   strings:
      $hex_string = { 772e6174746163684576656e7428276f6e6c6f6164272c2066756e6374696f6e28297b206f626a6563745b6174747269627574655d203d2076616c3b207d293b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
