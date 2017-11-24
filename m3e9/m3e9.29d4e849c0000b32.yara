
rule m3e9_29d4e849c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29d4e849c0000b32"
     cluster="m3e9.29d4e849c0000b32"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['0b0dddc555567dc313e81d1bf10e4e39','3f28885cf2d3cc5bec94aea16aa7937f','eb8d8425c6877e7494cf2da773f2d11a']"

   strings:
      $hex_string = { 004142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
