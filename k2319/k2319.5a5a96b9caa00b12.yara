
rule k2319_5a5a96b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a5a96b9caa00b12"
     cluster="k2319.5a5a96b9caa00b12"
     cluster_size="101"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem script"
     md5_hashes="['ab9fdc2655315079fcea19b91c13e8c295705cac','2dc2ff395fb7f4d77d9303f7e0e8a65a9114880b','5324310250bdc6e47da44e6c9064784ce57f445c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a5a96b9caa00b12"

   strings:
      $hex_string = { 44453f2835332e383045312c3331293a2830783136432c31313729293b7d2c58343d66756e6374696f6e28502c6b2c4f297b696628745b4f5d213d3d756e6465 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
