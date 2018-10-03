
rule m231b_4b983849c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.4b983849c8000b32"
     cluster="m231b.4b983849c8000b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clicker faceliker script"
     md5_hashes="['6f26e72b700defdf033e05caf3f82f3a18c5e3dd','bf84550c1681ff47fc6abf132e987c7978e7588d','9a61f3266a0a912550e4572a82ec2850913d4345']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.4b983849c8000b32"

   strings:
      $hex_string = { 323054254531254241254144702532303133273e54727579e1bb876e207472616e6820436f6e616e2054e1baad702031333c2f613e0a3c2f6c693e0a3c6c693e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
