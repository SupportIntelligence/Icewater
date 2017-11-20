
rule m2321_21156a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.21156a49c0000b32"
     cluster="m2321.21156a49c0000b32"
     cluster_size="127"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00da759c915789b442d54bdb0dd614d2','021e920cabed7792829e983f8bfc4c5b','22751cd3e53fe8fc5aa154a455ff2a8b']"

   strings:
      $hex_string = { a2448a94997370427558d77f69b827d0d6fb13a99e1a436597811237bbfd3698f8089c0c232f28726b25e75cdc2a9d53cb0f5ede8f478331c1e3e0ebc6ec10f0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
