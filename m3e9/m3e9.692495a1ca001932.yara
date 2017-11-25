
rule m3e9_692495a1ca001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692495a1ca001932"
     cluster="m3e9.692495a1ca001932"
     cluster_size="346"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob classic"
     md5_hashes="['02ab63a9c7cc17749a40b282cebca52f','04e6a2db86231435c32f9a5ec196e13c','17369227d2fd95213fa5683cd0520ede']"

   strings:
      $hex_string = { 5e3d0afa384a80d693fdff9304c4be745f3415fae8deefd693963704a5a9ad74703416fae1e8eef0b28e89a6a0a7b17561341afa00e8e5eeeff0a39c9fa14354 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
