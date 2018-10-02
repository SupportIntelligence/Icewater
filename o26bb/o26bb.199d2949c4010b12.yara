
rule o26bb_199d2949c4010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.199d2949c4010b12"
     cluster="o26bb.199d2949c4010b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious agen backdoor"
     md5_hashes="['85a0fe1dcd34daa1fc3471e77bdc2d6a4a327cc0','7fc006f590cf88dc743de0a3b56d68aceee065ac','ae1f2daba9c00053071be6691f99470c0f56e47d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.199d2949c4010b12"

   strings:
      $hex_string = { 87ffff0368011b03170751090affff0340000000030c006c626c436f707972696768740001010900436f707972696768740005d011f40b6f09ff001204002501 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
