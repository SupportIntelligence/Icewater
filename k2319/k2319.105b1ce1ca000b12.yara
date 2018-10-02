
rule k2319_105b1ce1ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.105b1ce1ca000b12"
     cluster="k2319.105b1ce1ca000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['72d93c8aa62bf74bac8458d498690aff3407e346','2a1131cec9eb2401bef18d5d256c13eb6f889dff','59305f36c63135b35b3c233e8ff1a88f8a311307']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.105b1ce1ca000b12"

   strings:
      $hex_string = { 3f2834372e393045312c313139293a2830783130362c34322e292929627265616b7d3b766172204c3264373d7b274c39273a66756e6374696f6e284c2c54297b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
