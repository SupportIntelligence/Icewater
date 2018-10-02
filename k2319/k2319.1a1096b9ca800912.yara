
rule k2319_1a1096b9ca800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1096b9ca800912"
     cluster="k2319.1a1096b9ca800912"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6c3840b4e07b350858052a08c676cc0e389d841e','4b3d0c81ae93d636421619020d8b5d648a256a67','9ffc3c13905af668393c3a47894276bdd9fbf77e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1096b9ca800912"

   strings:
      $hex_string = { 7834442c392e38354532292929627265616b7d3b666f72287661722077395720696e204d384b3957297b6966287739572e6c656e6774683d3d3d28307836443c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
