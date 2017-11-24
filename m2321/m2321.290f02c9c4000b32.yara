
rule m2321_290f02c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.290f02c9c4000b32"
     cluster="m2321.290f02c9c4000b32"
     cluster_size="185"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['0040cc320f0176fb9a2607234f3b2af5','00d53ac23c9c9289d631d4663d04410c','153de41a3b2d8919513e6b661a14ac9e']"

   strings:
      $hex_string = { 00c652b18ecc539dac9167dfad27ab04f1a0822c967dc087aa1db6b29bf9b924134006cdea3657eee655977f07e24d11aec9a90c8d6ade53b5c222ed666f548f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
