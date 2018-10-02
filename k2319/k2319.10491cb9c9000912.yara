
rule k2319_10491cb9c9000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.10491cb9c9000912"
     cluster="k2319.10491cb9c9000912"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['74b28d822227fff810366d56ad72cd243f6b4045','293e5d9a37be6f5bffb76c255017a28f45bc6681','2401d0ab12a8c9d6c061bf315df8ed7ae0017369']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.10491cb9c9000912"

   strings:
      $hex_string = { 28307846372c313333292929627265616b7d3b766172204b3068316c3d7b27423965273a226462222c2766336c273a66756e6374696f6e284f2c45297b726574 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
