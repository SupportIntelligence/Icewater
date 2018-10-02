
rule k2319_1a185ce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a185ce9c8800b12"
     cluster="k2319.1a185ce9c8800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['cf9c6591eebec4cea9edd8453ad717b1b3daafd4','367b34f57f8575235f09b2827db44da379b95804','277cdc777149ff1742a9dd52fc334bcc94cd5e61']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a185ce9c8800b12"

   strings:
      $hex_string = { 3a283132392c3134302e334531292929627265616b7d3b7661722042366b36483d7b27703367273a226e6473222c27683948273a66756e6374696f6e28572c70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
