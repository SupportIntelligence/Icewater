
rule k2321_29259166d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29259166d9eb1912"
     cluster="k2321.29259166d9eb1912"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys vbkrypt"
     md5_hashes="['00934e4bf8f7082b9a065cba2155cae8','28e316172e7983760608f885502642ec','f281f3fd798f79691eeac0190049e6e9']"

   strings:
      $hex_string = { 973a0a96f290b961f740fa38acf21ced33b4ba2182cbd50b7f51ea4e919e55722ae0327edd8e5c2822239750ee6b00a3d25e793cc067ab9deb99adec477705d8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
