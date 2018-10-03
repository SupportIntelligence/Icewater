
rule nfc8_6b1ccde9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.6b1ccde9ca800b32"
     cluster="nfc8.6b1ccde9ca800b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="stealer androidos fakeinst"
     md5_hashes="['5fef8e4a47feea7b85a99928155e4d64f814695f','525c07c43bdf7f311e910d8781ed20902d6e0fd6','380d873673804fb1a907400121271dcad546b0bb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.6b1ccde9ca800b32"

   strings:
      $hex_string = { dbcd5e6cc1840846b588e3b6e222581563f045bc0f1103b24898ae621ce47396302923b8cba3edc83a831fc521448c452ba1bf09f33bbe361ec67a1a3d7e86ee }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
