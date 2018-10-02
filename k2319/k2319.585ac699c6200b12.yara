
rule k2319_585ac699c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.585ac699c6200b12"
     cluster="k2319.585ac699c6200b12"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['41dbceef4fc253b1d0d7c98ac6a5ad4f23da5474','60484ec9b573bf1daef5ae9caea6966fba402331','4ac88c2f32aecedea9f270688b590d068b42167a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.585ac699c6200b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e2067375b535d3b7d766172206f3d2828372e3945312c30784236293c34342e3f2831302e373645322c307843 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
