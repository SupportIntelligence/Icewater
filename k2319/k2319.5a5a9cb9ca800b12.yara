
rule k2319_5a5a9cb9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a5a9cb9ca800b12"
     cluster="k2319.5a5a9cb9ca800b12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['55bcf78c5e74977f0c3e7822738de840a25d6ee0','0d51625c00eb2d9f2e238f8fda1ba18d237a70a3','e0323cb504bc8ac82907c9123807711436f21c12']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a5a9cb9ca800b12"

   strings:
      $hex_string = { 44453f2835332e383045312c3331293a2830783136432c31313729293b7d2c58343d66756e6374696f6e28502c6b2c4f297b696628745b4f5d213d3d756e6465 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
