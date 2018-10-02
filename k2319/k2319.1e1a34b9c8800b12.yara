
rule k2319_1e1a34b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1a34b9c8800b12"
     cluster="k2319.1e1a34b9c8800b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['92a27929105f47c3892383014932ec5d84e03445','7f3bdc7a6e230a7f005dff33aaf3f5e7da4672ce','ff16e452c12128e1c8d4453d349c52e5ff5feed4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1a34b9c8800b12"

   strings:
      $hex_string = { 72222c2758334a273a2866756e6374696f6e28297b76617220433d66756e6374696f6e286b2c53297b76617220453d53262828307842332c34322e364531293e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
