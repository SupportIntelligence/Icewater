
rule m2321_1930ca6ade8bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1930ca6ade8bd912"
     cluster="m2321.1930ca6ade8bd912"
     cluster_size="20"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0287b5e3dda28392a204f68c0b9c56a0','09754441bb8f87bd855842f5ac38cf63','bca802fcfc5fe92fe6a599bf938dfbbb']"

   strings:
      $hex_string = { 5d00091b9e6cf55fa417abbd05cfcc4cdcbf6077d3f66ed16468f22d28ffb7a0fc8fea616f248b88c2bee230ae2fb655b5f8dc81d9c40ed7163578b9fd42d251 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
