
rule k2319_1e194eb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e194eb9c8800b12"
     cluster="k2319.1e194eb9c8800b12"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['284e3d6a2908edfa31268867508cb6897741f49e','1178bdec0df2dc7eb3f348b689187047c957418a','e4e5e21cbb540c17e2efb182704b77baec186cb6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e194eb9c8800b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20465b585d3b7d766172206e3d28342e333245323e28307837302c313039293f2830783139362c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
