
rule k2321_291b0ab9ca200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.291b0ab9ca200b32"
     cluster="k2321.291b0ab9ca200b32"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol servstart cfecc"
     md5_hashes="['056dbe0e484f276cc080db04679b37eb','3f31e49a974cda6776f9c7db7b2eb7d3','e3dab9aab670f9e24aa01374c6a516e1']"

   strings:
      $hex_string = { 6165642d8db7235d7ca5c55138e1d7743abf7e44d36973fdd0b47fddbbefa35da19dd6579bdebd6e5f04e3bcf555cadf95904719b9594eb030fe7b071eff571d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
