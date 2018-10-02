
rule k2319_39159aa9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39159aa9c8800b12"
     cluster="k2319.39159aa9c8800b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5eb35117edbd92f8fbdb41278dfecc553596aca4','73684483434cee11a97ba0f480475162052b9635','1bfd354c1f27aa4fb3f5b6b1e4c395b4f4143f5c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39159aa9c8800b12"

   strings:
      $hex_string = { 322c312e30344533292929627265616b7d3b76617220573957363d7b274730273a66756e6374696f6e28592c43297b72657475726e20593e433b7d2c27763846 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
