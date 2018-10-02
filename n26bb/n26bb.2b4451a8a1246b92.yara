
rule n26bb_2b4451a8a1246b92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2b4451a8a1246b92"
     cluster="n26bb.2b4451a8a1246b92"
     cluster_size="297"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="slimware unwanted driverupdate"
     md5_hashes="['2b6cd6c3132234554f9553fc76c1426bf2f61468','5a2309765c37f9355b0b5d6cfc034d97353113a0','c9286e74ea33a5084afe7e1f3697e3bce6aa5695']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2b4451a8a1246b92"

   strings:
      $hex_string = { 57e644000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
