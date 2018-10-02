
rule k2319_5a5a94b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a5a94b9ca200b12"
     cluster="k2319.5a5a94b9ca200b12"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e10d2d84d9543f9bee28c1322412a76555b11730','e8383f1de21a37ace79fd28d6762f061bbd7254f','5eaa51745bc9da25a3d22045fc209aac98d7376d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a5a94b9ca200b12"

   strings:
      $hex_string = { 44453f2835332e383045312c3331293a2830783136432c31313729293b7d2c58343d66756e6374696f6e28502c6b2c4f297b696628745b4f5d213d3d756e6465 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
