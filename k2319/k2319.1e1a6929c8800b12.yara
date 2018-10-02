
rule k2319_1e1a6929c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1a6929c8800b12"
     cluster="k2319.1e1a6929c8800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['11def92c056c48c729f043b57cd553ab411df5f9','3b3cb17418edc20e7836b8d12f914d0e4f51dc31','8da1498f06947aa7a2ec44ef8b8905eccbeeaa0c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1a6929c8800b12"

   strings:
      $hex_string = { 72222c2758334a273a2866756e6374696f6e28297b76617220433d66756e6374696f6e286b2c53297b76617220453d53262828307842332c34322e364531293e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
