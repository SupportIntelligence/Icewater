
rule k2319_101994b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.101994b9c8800b12"
     cluster="k2319.101994b9c8800b12"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['28c3babf4fd5726f8869c9e4879e294ec1813910','0bf6b456316f53b1bca05cdaac529f3993f7d9a3','9c89614fb08b85136517e8bec0b3da66a0134ddd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.101994b9c8800b12"

   strings:
      $hex_string = { 3f2830783141352c313139293a28332e343745322c3078323137292929627265616b7d3b76617220573745364d3d7b2754364d273a66756e6374696f6e284e2c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
