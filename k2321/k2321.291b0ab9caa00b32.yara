
rule k2321_291b0ab9caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.291b0ab9caa00b32"
     cluster="k2321.291b0ab9caa00b32"
     cluster_size="21"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol servstart cfecc"
     md5_hashes="['0597cadd63b216dfe6d4b7199a7393d9','174b5f6f4635a2c1145a98c208e41025','deb341ed1dda6b5d05a97d8bf2f9eb9a']"

   strings:
      $hex_string = { 6165642d8db7235d7ca5c55138e1d7743abf7e44d36973fdd0b47fddbbefa35da19dd6579bdebd6e5f04e3bcf555cadf95904719b9594eb030fe7b071eff571d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
