
rule o422_19e916c2c8001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o422.19e916c2c8001132"
     cluster="o422.19e916c2c8001132"
     cluster_size="9069"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitminer bitcoinminer coinminer"
     md5_hashes="['7cfcd645169880deab396c83e39b2a956e9c0c23','d6e430884795cf450961c21a07d61d9402624602','12184482d6ddbb1c7982ea1b0409a3f2c9067c18']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o422.19e916c2c8001132"

   strings:
      $hex_string = { 0310b6f003009af30310a5f30310d1f70310eff70310d8fb0310f6fd0310e6000410a0090400df0a041081110400f91404108b150410b9150410c4180400c11b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
