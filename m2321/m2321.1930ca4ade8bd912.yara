
rule m2321_1930ca4ade8bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1930ca4ade8bd912"
     cluster="m2321.1930ca4ade8bd912"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0777dede837a39f52bc654351ba973b6','1f85cfdc512241c7848b157e290d7e45','f46f7537d5c013b080a7023e690c46f7']"

   strings:
      $hex_string = { 5d00091b9e6cf55fa417abbd05cfcc4cdcbf6077d3f66ed16468f22d28ffb7a0fc8fea616f248b88c2bee230ae2fb655b5f8dc81d9c40ed7163578b9fd42d251 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
