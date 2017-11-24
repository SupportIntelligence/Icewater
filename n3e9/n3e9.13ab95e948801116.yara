
rule n3e9_13ab95e948801116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13ab95e948801116"
     cluster="n3e9.13ab95e948801116"
     cluster_size="40"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun blocker"
     md5_hashes="['179483c3d649955e840f7527cc20c13d','19c889a1394b99df779a14ed7eab0d1f','ab8aa92b8d2acfdfc531b66cdb719b05']"

   strings:
      $hex_string = { 3cbbafac1bcfe4f08b30fb159e812796abe1bd5b49e93fa7c9de583ea355be6317d59ff401569b5210c893903848ac842a59c776d7cc124aa65efca0eb22c52b }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
