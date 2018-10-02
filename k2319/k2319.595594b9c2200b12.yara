
rule k2319_595594b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.595594b9c2200b12"
     cluster="k2319.595594b9c2200b12"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['0e82a8f92ea958fd6a7f8949f2c64ec62eea477b','4c4890eb97a69b5dae797e3d8440565315416014','38a6e0bfb88187d991f328d26ab29325c7c4ed77']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.595594b9c2200b12"

   strings:
      $hex_string = { 3a2833332e3545312c342e38384532292929627265616b7d3b76617220653674365a3d7b27453474273a2277222c2741315a273a66756e6374696f6e28542c43 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
