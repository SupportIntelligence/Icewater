
rule m2321_139d6a49c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.139d6a49c0000b16"
     cluster="m2321.139d6a49c0000b16"
     cluster_size="16"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar deepscan pwstealer"
     md5_hashes="['15edd941df4975373b477f37dec7c3d0','18bf365f3e948ac9a926ead2f1abe6b1','e92e250fc8657066f69e8d5417c2caeb']"

   strings:
      $hex_string = { bfd117e0a465dc019fe4872667c3e92d1655fb6acf1a4d71da05c540a7a185c920a875c8f4a582c13014f61d356c283c0b66c0810e3e76aead9238b9dc6157ca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
