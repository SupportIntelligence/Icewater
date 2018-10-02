
rule k2319_181ad6b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181ad6b9c2200b12"
     cluster="k2319.181ad6b9c2200b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b4a4f63e428f618a900673a7095f40577b8d0cee','f6bf118a278d001ea46faeea9fd5bb1d8852f759','d7d452754db1d3951dd4c24cca241fbd8edb4e27']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181ad6b9c2200b12"

   strings:
      $hex_string = { 35313045333a28392e3845322c322e32374532292929627265616b7d3b7661722073385338383d7b27473642273a6e756c6c2c27413838273a66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
