
rule j2321_29274286cdbb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.29274286cdbb0b32"
     cluster="j2321.29274286cdbb0b32"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader generickd"
     md5_hashes="['051ded83f0fbd4e3187148d5ce1fd993','2f1f61eb2ff94e4aa4199de45368f00e','f7618097564dcb930de5e5cc17806645']"

   strings:
      $hex_string = { 12b537a0cf529a1eef95715166b98514e1e674dc483f0beb66924f45b032bd889619ac6c3ca7208c7abf068a6a8cc66b83c0a85327c0d413d861f7759cd96f38 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
