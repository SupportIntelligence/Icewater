
rule k2321_23d5eccd96264aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.23d5eccd96264aba"
     cluster="k2321.23d5eccd96264aba"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['099e43c261dd4cadfa6e24a0507c9618','18f6c6faacfd3281d89a79834269de60','e45ef97abc9dfa6efbd045acaee2445f']"

   strings:
      $hex_string = { e18ceca271f9d2845cf49af4e45c724d62cac412e9f0dce269e3f2a4434ba665e64e491f1e1ba9c6293c6850522c5777ea3e90b7351df71491cf805588e701d6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
