
rule k2319_181096b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181096b9ca800b12"
     cluster="k2319.181096b9ca800b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['849e7344b100e061b6cbf97d1e3a914f3c99141a','92e3280c2e0c2aa61a149554486deb7336704a1d','e80a823c239fedb8efd1e321eab0169acc3b03f4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181096b9ca800b12"

   strings:
      $hex_string = { 352c313139293a28307842372c39332e344531292929627265616b7d3b7661722061335036553d7b2750304f273a352c274a3655273a66756e6374696f6e2856 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
