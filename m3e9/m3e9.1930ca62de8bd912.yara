
rule m3e9_1930ca62de8bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1930ca62de8bd912"
     cluster="m3e9.1930ca62de8bd912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['2c4cb4e3489d955b12af8317858735f7','6b79f72aeb79730f0937aebb89546d92','c2271f82b710b9cd7e5cb99e868574b3']"

   strings:
      $hex_string = { 5d00091b9e6cf55fa417abbd05cfcc4cdcbf6077d3f66ed16468f22d28ffb7a0fc8fea616f248b88c2bee230ae2fb655b5f8dc81d9c40ed7163578b9fd42d251 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
