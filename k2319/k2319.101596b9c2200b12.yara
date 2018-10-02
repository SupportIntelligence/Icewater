
rule k2319_101596b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.101596b9c2200b12"
     cluster="k2319.101596b9c2200b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e110226f2f319f2675ca2ea6d895bc2315bf9d13','9fc9fdc966566647537e8d9a7c4f218af10c1711','a966a78f2267922f753454749dabb5bb132bb302']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.101596b9c2200b12"

   strings:
      $hex_string = { 45323f2834372e393045312c313139293a2830783131392c3078314137292929627265616b7d3b766172206f3862336c3d7b2777336c273a66756e6374696f6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
