
rule k2319_10159cb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.10159cb9c8800b12"
     cluster="k2319.10159cb9c8800b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5bbae04c97481e235f6860c20ddf3a48850f601a','c6153650fac8f72c16747eb0d58cff916840e187','491e943aec3e4b00c348c7da20da5c248322f4f4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.10159cb9c8800b12"

   strings:
      $hex_string = { 45323f2834372e393045312c313139293a2830783131392c3078314137292929627265616b7d3b766172206f3862336c3d7b2777336c273a66756e6374696f6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
