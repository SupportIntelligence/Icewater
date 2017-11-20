
rule m2321_03322524dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.03322524dec30912"
     cluster="m2321.03322524dec30912"
     cluster_size="69"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi download socelars"
     md5_hashes="['0341bffcd6cfeca4b1935880dbd45e5e','057d796d2620bd01ae245ab4b7b7e0fa','39742ea9457a4181d5a7b0622daa210b']"

   strings:
      $hex_string = { 81117e446b951baa7a883d83682d129f277692c711063eab29143639dbf8fa1fe1da5fbe6589212be4e3dc01aed14df7af6773d5bb829985f27861f95da524c1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
