
rule m3e9_6e4afac9c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6e4afac9c4000912"
     cluster="m3e9.6e4afac9c4000912"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy adload nsis"
     md5_hashes="['2d611ffabd265aacbc72d42f90b6aca6','63f57c71b7c5764a5fba6d4b7f81a0b0','9d3fc60fa323ab0a286218996edae597']"

   strings:
      $hex_string = { aa39af39b5393c3ab33ac23ad83aed3af93a433bc33c2a3e763e803e9a3e7c3f000000200000ac00000037303e30b7302e317532dc32ed32fd321b3322334433 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
