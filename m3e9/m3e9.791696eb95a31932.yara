
rule m3e9_791696eb95a31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.791696eb95a31932"
     cluster="m3e9.791696eb95a31932"
     cluster_size="571"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['000d9ef4489ebab99281033701e3c953','00b748ef184330b52a060062d5c9187f','09fc225c5add80ad7760b7bb54d0e3f7']"

   strings:
      $hex_string = { 72bf8b45ec8b4d208d340833c96a045a8bc6f7e20f90c1c745fc01000000f7d90bc851e849fdfeff5956508d4b14e86909ffff837b1800750ab80e000780e96b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
