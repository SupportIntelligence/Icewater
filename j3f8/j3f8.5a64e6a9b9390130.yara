
rule j3f8_5a64e6a9b9390130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5a64e6a9b9390130"
     cluster="j3f8.5a64e6a9b9390130"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos bddf"
     md5_hashes="['6e5dfc07bfbfbf36339fb60be068f6ba32ff3789','376ca554c355ea950ea6e789d1a75038cc8a81a0','546980591fdccbc16148fcbcc0c6e14efa0c0637']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5a64e6a9b9390130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
