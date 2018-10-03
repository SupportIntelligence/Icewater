
rule i2319_15b9d062dc66e131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.15b9d062dc66e131"
     cluster="i2319.15b9d062dc66e131"
     cluster_size="128"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html script"
     md5_hashes="['0b2b92a293f3cf29990e091db95f491b7372d23e','a71f2c2916c63706b70f5ecf478af3c0eaf05e66','bd3d36052f8eb6743ac51dc0df982744018af65e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.15b9d062dc66e131"

   strings:
      $hex_string = { 772e77332e6f72672f313939392f7868746d6c223e0d0a3c686561643e0d0a3c6d65746120687474702d65717569763d22436f6e74656e742d54797065222063 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
