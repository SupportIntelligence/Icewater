
rule j2319_292f2534ea208932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.292f2534ea208932"
     cluster="j2319.292f2534ea208932"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script html redirector"
     md5_hashes="['ea2b5363ab6d581218985ed40685313ca75574eb','a30edf7884d0e4d30d4203c1c2a603d3664f3b98','4ac1996b1b0bdb878dda8b27b897fcf2fb3b49fa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.292f2534ea208932"

   strings:
      $hex_string = { 2e7068703f67325f766965773d696d6167656672616d652e43535326616d703b67325f6672616d65733d6e6f6e65253743646f7473222f3e0a3c6c696e6b2072 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
