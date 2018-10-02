
rule k2319_1a569cb9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a569cb9c2200b12"
     cluster="k2319.1a569cb9c2200b12"
     cluster_size="65"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['f3ff025758e8ea503d61152f1b5f7db455e8a2f8','bcde421c7365163370458297edd22f513e1d99b7','bce2842d1df7319b14496b4c66aef8818aafb15a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a569cb9c2200b12"

   strings:
      $hex_string = { 32383f2839372c274627293a2830783130392c362e36364532292929627265616b7d3b7661722062385138713d7b276c3971273a66756e6374696f6e28522c70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
