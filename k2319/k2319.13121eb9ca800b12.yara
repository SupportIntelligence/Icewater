
rule k2319_13121eb9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.13121eb9ca800b12"
     cluster="k2319.13121eb9ca800b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['98700803f3101502d54d9ba960ea88f90b700781','b19d305966ba1bc4fe6b84b61de7db0430bc2e13','47720853ef6fc912e24fcda90c6e92e543fdaccb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.13121eb9ca800b12"

   strings:
      $hex_string = { 3078323044293f2837352e2c313139293a2837332e3345312c39312e292929627265616b7d3b766172206c395a376a3d7b2757356a273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
