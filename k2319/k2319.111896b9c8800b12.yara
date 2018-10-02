
rule k2319_111896b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.111896b9c8800b12"
     cluster="k2319.111896b9c8800b12"
     cluster_size="103"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b8dfe3b52ccdea79319f6bd19d2c0936798ed922','fb90af0b528553625b26bd42ab8affb6cd54c918','5101255f6790ab4191e72964354f51a3cfda14ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.111896b9c8800b12"

   strings:
      $hex_string = { 3e307841463f28352e343645322c313139293a2835362c3078313945292929627265616b7d3b7661722076375a39433d7b277a3138273a22696a222c27743738 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
