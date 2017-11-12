
rule m3e9_693f852499eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f852499eb1912"
     cluster="m3e9.693f852499eb1912"
     cluster_size="278"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['043ecaca03e4d798be389462d58aa62f','04a0bdbcb3c0febf14f19a0ce696043c','3147c188386a5ff8fa7d2478179dca5d']"

   strings:
      $hex_string = { 599675977f069856c885bc8e9795faee915382ebbac40a95ebffcd04441cfba085364b91193123aad2f7c4c8ff7ec6ff7dc5c628623ca97efe33829a5fefc821 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
