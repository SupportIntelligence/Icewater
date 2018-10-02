
rule k2319_193394e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.193394e9c8000b12"
     cluster="k2319.193394e9c8000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['3ebf6a1e5d50de35f7b08ffb70b300c439c9268d','80fe26eccb3dd5c337997a6bfe0c34f66103442d','bf85b2712005d6f85983bcaefe97c407bccee052']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.193394e9c8000b12"

   strings:
      $hex_string = { 505d213d3d756e646566696e6564297b72657475726e20765b505d3b7d76617220443d28283078362c313335293e3d35342e3f28342e313945322c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
