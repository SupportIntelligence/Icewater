
rule n2321_33905bb9c9800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.33905bb9c9800b32"
     cluster="n2321.33905bb9c9800b32"
     cluster_size="18"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="driverupdate fakedriverupdate heuristic"
     md5_hashes="['0fd2003172e8833f473d922939da1075','15ae9f2716fee8ca79511252265f8463','e00eb9904c1c47caef4434321a38b2aa']"

   strings:
      $hex_string = { 2d90d6495f5003530c8f057b6892566b817906eb12fbd5097a368abc22af39694cd8ddec9d6338e760ccd3bbcd4a83db66ee889a4b2e9ba1317c5c72071fe85d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
