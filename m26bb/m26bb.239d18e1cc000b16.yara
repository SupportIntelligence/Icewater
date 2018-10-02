
rule m26bb_239d18e1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.239d18e1cc000b16"
     cluster="m26bb.239d18e1cc000b16"
     cluster_size="48"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="based remoteadmin winvnc"
     md5_hashes="['f7545e8f6be656d9ee1b54a239689f692c10aab2','211086974f4af6abcbac18d289228bd5252ba37a','099c361906773770562bd9db081402bd999e8d81']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.239d18e1cc000b16"

   strings:
      $hex_string = { 742408578a460f3a420f75210fb6c833ff85c976118bc22bf28a14063a10750d47403bf972f3b0015f5ec2080032c0ebf7b8132d4100e815aa00005153568bf1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
