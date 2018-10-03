
rule k2318_311917a9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.311917a9ca000b32"
     cluster="k2318.311917a9ca000b32"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['ffc4cc0c228b7714791af7ddef4b73bc62b15fb7','2cdf3950b82be643e86f06ea4bbe92ecc83b07a2','f366d3ec61e1a448906a456871bd8b33f639a26e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.311917a9ca000b32"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
