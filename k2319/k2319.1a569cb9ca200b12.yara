
rule k2319_1a569cb9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a569cb9ca200b12"
     cluster="k2319.1a569cb9ca200b12"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['93edf78767784feb4674ffc139e8b7e809a9255c','77c0a9765f7ccd7a97405057b7a26737b4e1301c','3d0efa9786dc4ddd488f2beb993da4c0926ccea1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a569cb9ca200b12"

   strings:
      $hex_string = { 32383f2839372c274627293a2830783130392c362e36364532292929627265616b7d3b7661722062385138713d7b276c3971273a66756e6374696f6e28522c70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
