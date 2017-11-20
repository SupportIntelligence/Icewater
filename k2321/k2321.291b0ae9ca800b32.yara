
rule k2321_291b0ae9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.291b0ae9ca800b32"
     cluster="k2321.291b0ae9ca800b32"
     cluster_size="16"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol servstart cfecc"
     md5_hashes="['1b595e7095526a52e0ed4d62f62cdace','1f86ca48059de0aae65ca5a8bed4547c','fb0abcfb38dce4147a276a7f0e767fe5']"

   strings:
      $hex_string = { 6165642d8db7235d7ca5c55138e1d7743abf7e44d36973fdd0b47fddbbefa35da19dd6579bdebd6e5f04e3bcf555cadf95904719b9594eb030fe7b071eff571d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
