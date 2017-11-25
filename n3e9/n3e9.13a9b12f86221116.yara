
rule n3e9_13a9b12f86221116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13a9b12f86221116"
     cluster="n3e9.13a9b12f86221116"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun blocker"
     md5_hashes="['67c8a0b0005558b0d359622da06e5c00','ad2b488683d449412f2c957c4545aab0','b4daeacdd73086ca9ffc406ff083a2e6']"

   strings:
      $hex_string = { c8d165d2a969648e940896fd9c55e5d7389575cdf5f90f9d74360d5f5e862721c0611e6f58d847b9c3044c88b64bd4bd721b89a1b7cc14436f62ab4d03a30225 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
