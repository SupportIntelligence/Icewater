
rule k2319_69073949c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.69073949c0000932"
     cluster="k2319.69073949c0000932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script asmalwsc"
     md5_hashes="['5c3c149e073e331d07c70ff93a8615e25c7f8056','fb5e1416705414cad414a7a20146a4350a841912','c90d992f1b3a0422629b9ec5fcd4e08d7bcfedff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.69073949c0000932"

   strings:
      $hex_string = { 75297b72657475726e20612f753b7d7d3b2866756e6374696f6e28297b7661722072323d226f77222c41323d227368222c71303d22744c222c70323d22644576 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
