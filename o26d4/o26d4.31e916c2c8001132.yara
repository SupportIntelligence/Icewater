
rule o26d4_31e916c2c8001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.31e916c2c8001132"
     cluster="o26d4.31e916c2c8001132"
     cluster_size="168"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitminer riskware bitcoinminer"
     md5_hashes="['654768d622fccf89ec97f50636f73388cd0b73e2','658d9d2989fca964124277cc3280c5c7abff707b','ff8dd82450533c1c56d4c7a2767833b9b0d798c1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.31e916c2c8001132"

   strings:
      $hex_string = { 0310b6f003009af30310a5f30310d1f70310eff70310d8fb0310f6fd0310e6000410a0090400df0a041081110400f91404108b150410b9150410c4180400c11b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
