
rule k2321_219c6a49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.219c6a49c0000932"
     cluster="k2321.219c6a49c0000932"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol fdld dropped"
     md5_hashes="['4d5ae01d817c9c5f2452c0f1aa327f90','54696f4dc442cddf35cc690f77f0529b','9e6cb5e80737a78a48ae32f2b49aebaa']"

   strings:
      $hex_string = { d32f4c506cea84c5a651b16f726d8b0e58b1e69ff0c7ba9d780cce37c9c2e74d91b64f48c0ad9554fdd6f3acdf7a810d68cf860267f587b47ffa650929061b34 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
