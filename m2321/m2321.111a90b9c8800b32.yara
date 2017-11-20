
rule m2321_111a90b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.111a90b9c8800b32"
     cluster="m2321.111a90b9c8800b32"
     cluster_size="20"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz banker"
     md5_hashes="['18e80193c28a90a167f3944ad25321dd','21213affea27d6d4c0df0d6acca84851','cc46ed154dfae5c053580cf4a10f2972']"

   strings:
      $hex_string = { 4637a62bdda2c051c2054ae124c1e5484380c788acb608d2542f272891f4d3ef66894d952296fb25132649b612dcbde73452f744141b2eced0f078b430156031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
