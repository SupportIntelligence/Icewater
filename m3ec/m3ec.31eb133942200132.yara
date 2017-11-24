
rule m3ec_31eb133942200132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.31eb133942200132"
     cluster="m3ec.31eb133942200132"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob classic"
     md5_hashes="['1166ac1416e6b4784ea57d34014e2960','116a3a222c81e73b6d7cf5bf3b43acac','cfad54d4e41f23661b5de16ff4f80b82']"

   strings:
      $hex_string = { 002e000a0006010a00550073006100670065003a0020002500310021007300210020005b005b006e0061006d0065003d005d003c0073007400720069006e0067 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
