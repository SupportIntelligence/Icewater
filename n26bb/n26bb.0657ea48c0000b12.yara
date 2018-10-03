
rule n26bb_0657ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.0657ea48c0000b12"
     cluster="n26bb.0657ea48c0000b12"
     cluster_size="141"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom gandcrypt"
     md5_hashes="['eec8c1fa4b113bfa01366091469e130063449389','75290bee0ce1755dcc917d6467a51b88d460b624','1a87eaea9fe6401ed2d3c66448f9730174c5787d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.0657ea48c0000b12"

   strings:
      $hex_string = { ecc140000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
