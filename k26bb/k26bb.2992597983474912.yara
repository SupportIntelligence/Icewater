
rule k26bb_2992597983474912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.2992597983474912"
     cluster="k26bb.2992597983474912"
     cluster_size="62280"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installmonster bundler nsis"
     md5_hashes="['4c3c5d64b198a23ee38348de8fb86effe3f71349','e02a3b00ecf2babb3d5f013e8b896753ebb9a95e','d9266993ebadb51b1229e0601b18c72140fb24fd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.2992597983474912"

   strings:
      $hex_string = { 4e08ebd68b4c2404a1e82d47005633f683f92073363935ec2d4700762e8d5008578b02a806751433ff47d3e7857afc740583c801eb0383e0fe89024681c22040 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
