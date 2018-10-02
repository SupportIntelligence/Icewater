
rule k2319_690f3949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.690f3949c0000b12"
     cluster="k2319.690f3949c0000b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browext"
     md5_hashes="['0519faee7c32e174ccb416a32a232c47b363a47a','1e761d620078ea5235a1222983251d355e16a6dd','c07248ddf66568a0d6d1d503a98c77d408a3d905']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.690f3949c0000b12"

   strings:
      $hex_string = { 7d3b2866756e6374696f6e28297b7661722072363d226f77222c56363d227368222c6d303d224576222c70303d227461222c6b303d282838352e2c3078313744 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
