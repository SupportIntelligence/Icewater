
rule j3f7_611eea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.611eea48c0000b32"
     cluster="j3f7.611eea48c0000b32"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html iframeref"
     md5_hashes="['17fad42cb1c2c76b1880646edcf0b2b6','3ea05b5a2f4938caa438e2e8af3d6c39','edf72b2cb175c8833e30bd8f324cd02c']"

   strings:
      $hex_string = { 6c65743e3c2f666f6e743e3c736372697074206c616e67756167653d226a61766173637269707422207372633d22687474703a2f2f666174616c2e72752f6164 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
