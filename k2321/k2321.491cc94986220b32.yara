
rule k2321_491cc94986220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.491cc94986220b32"
     cluster="k2321.491cc94986220b32"
     cluster_size="20"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms risktool uvpm"
     md5_hashes="['060606bfd5d09e416cb09258ad2c3639','07f4059173b404bd065e8fbca9ede54c','dfc741ef0df30b67e6e96049e21a8231']"

   strings:
      $hex_string = { dbfac2a21441f38ebb6a89edf1ef73a4ca80f26b56a5e4c9d7d587a97572c5967edee394bac6ec7d57f8c4fc82f0e2d80579d3ce65b81b49f5539e9235025b88 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
