
rule k2319_59559699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.59559699c2200b12"
     cluster="k2319.59559699c2200b12"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['3f4d88be28a7a2f8141528ba0836ce51efafb43d','7c0a71d4755ebca8f7a93a37e2892f8eda855aad','4929aae1a1beaaa52f47b4716d49fc1036c598cd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.59559699c2200b12"

   strings:
      $hex_string = { 3a2833332e3545312c342e38384532292929627265616b7d3b76617220653674365a3d7b27453474273a2277222c2741315a273a66756e6374696f6e28542c43 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
