
rule k2321_291c9299c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.291c9299c2200912"
     cluster="k2321.291c9299c2200912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['2cfb68d4579ebb30ee665c541d997356','5d31329a3884b129f124b7176e633a00','f2eb6cdcd15bd2bea4b360f7714bd5b9']"

   strings:
      $hex_string = { 16aadff7304d7eb5cfcc72698b092d97991d529566de1e0bc49afaace34f98b8bcfc90c2a86525cb0e35e807a99d4b6ea26d7c47d013383a7541a4eaf3f9a58d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
