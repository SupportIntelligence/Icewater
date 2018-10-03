
rule n26bb_06d56849c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.06d56849c0000b12"
     cluster="n26bb.06d56849c0000b12"
     cluster_size="158"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy gandcrab kryptik"
     md5_hashes="['4006dbdf6bdf5778d67326094c5706126237ae75','01255a7c9c6272b5ad1dab44f77e44068ca63052','33758d066e8047245702a8ceb25c02a706c8b3b8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.06d56849c0000b12"

   strings:
      $hex_string = { dcc140000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
