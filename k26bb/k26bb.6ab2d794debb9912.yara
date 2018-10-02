
rule k26bb_6ab2d794debb9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6ab2d794debb9912"
     cluster="k26bb.6ab2d794debb9912"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo filerepmetagen malicious"
     md5_hashes="['7896d2f0898b3ed4b835ff33b8e2c81fdd1d0ef1','19e349241f4ca7346eef9f1293f72994f20f1832','a62225918cff3b7f30b060b5d94fa0d36fc86adc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6ab2d794debb9912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
