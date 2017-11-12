
rule m3e9_6b2f2525d9bb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f2525d9bb1b12"
     cluster="m3e9.6b2f2525d9bb1b12"
     cluster_size="16"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['0b9238b8345406c0f398e0e45fda7705','6de5385742ab24a01ae50d83c8492e64','f3497bed4d54c6e3104566f03cde21a4']"

   strings:
      $hex_string = { 599675977f069856c885bc8e9795faee915382ebbac40a95ebffcd04441cfba085364b91193123aad2f7c4c8ff7ec6ff7dc5c628623ca97efe33829a5fefc821 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
