
rule m3e9_23322524dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.23322524dec30912"
     cluster="m3e9.23322524dec30912"
     cluster_size="33"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi socelars socstealer"
     md5_hashes="['0c79eaba5d115216dffa1064b55c354c','121ee6a9c9eeec405c49450d38ad29ca','83fff5ca57e57ef83f9e81dacc042149']"

   strings:
      $hex_string = { 81117e446b951baa7a883d83682d129f277692c711063eab29143639dbf8fa1fe1da5fbe6589212be4e3dc01aed14df7af6773d5bb829985f27861f95da524c1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
