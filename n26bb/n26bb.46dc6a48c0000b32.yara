
rule n26bb_46dc6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.46dc6a48c0000b32"
     cluster="n26bb.46dc6a48c0000b32"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom malicious"
     md5_hashes="['a73dbf4e4176a01315abff3653a51ff046ceefcf','ff4adce440b72aaae51037a7a38221d0d709d451','24cc3dfbdc6fe9f0bbfe2394e7d252a7981b7395']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.46dc6a48c0000b32"

   strings:
      $hex_string = { f0b440000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
