
rule k2319_120a96b9c9000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.120a96b9c9000912"
     cluster="k2319.120a96b9c9000912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['f980c45e194b3653ee6818e8db6c1137f0438521','6a35482f99a14394c8b4df1ef2708c2b0e77f3c3','473e4c6b8b053368b292c46de78bfccf1d77f2c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.120a96b9c9000912"

   strings:
      $hex_string = { 3f28312e30333645332c313139293a2839362e3545312c30783141292929627265616b7d3b76617220793559376c3d7b2751396c273a66756e6374696f6e286a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
