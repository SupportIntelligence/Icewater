
rule m2321_391c3ac1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.391c3ac1cc000b16"
     cluster="m2321.391c3ac1cc000b16"
     cluster_size="519"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi gamarue buzus"
     md5_hashes="['00b07ccbe915ed77c4965da5835600cb','00ea841d5adcf0835f6c2a0111cef1b6','05841578dac47638d29eb7ffe91a369b']"

   strings:
      $hex_string = { d43689f38c0e0f3295ae546f63cd04b0a2e8fabd263c463a4790ec92496e3ba1184f17ba938eff0c9177e3c3d2e541e2378d22ef6168c0c219a61eaad5c5796d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
