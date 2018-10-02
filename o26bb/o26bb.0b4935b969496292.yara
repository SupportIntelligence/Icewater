
rule o26bb_0b4935b969496292
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.0b4935b969496292"
     cluster="o26bb.0b4935b969496292"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mdeclass btcmine score"
     md5_hashes="['ebdc0c772ee217a91b87635beef98a5b9a36cca6','fd105087249a8c4e21a02afa104ca20f79ca254a','bec538e4f75c4e082ca13858bf4ef6d3d0861a78']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.0b4935b969496292"

   strings:
      $hex_string = { bf14fe9fa078fdf73b3c884c80679e3ad981da36ad04f58446b087bb5b4ec061ae8f05f11f40f200901c49f0432382a89327ee0e086b55415916e3a6b64d2b83 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
