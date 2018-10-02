
rule m26bb_75356a56dd82f132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.75356a56dd82f132"
     cluster="m26bb.75356a56dd82f132"
     cluster_size="102"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom malicious"
     md5_hashes="['afab2e49e924e8fb30029bafa9c8e14effe41443','1ad7f05013c5aafdc7831b374b27571047ef11eb','8967503cf454555466f14be61a4cb84e84397394']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.75356a56dd82f132"

   strings:
      $hex_string = { 42b640000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
