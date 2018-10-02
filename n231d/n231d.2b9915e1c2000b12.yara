
rule n231d_2b9915e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.2b9915e1c2000b12"
     cluster="n231d.2b9915e1c2000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos oversea risktool"
     md5_hashes="['d3a2a7a1ff5fcd566fcbf30c6da0968941a6d0ee','76143af520a98f6013f36dded97bd110eace5451','f146e6e87e7df15c2f6f554104f0b13436a3aa79']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.2b9915e1c2000b12"

   strings:
      $hex_string = { c58c1b84082fc7fe43b13db8ce57868927a0d70accaea609a8f5d6e16f65e2ee1e5bf63ce617be5d8b91558053288fc9c60123c2d81d8751db03b7b631e99f5f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
