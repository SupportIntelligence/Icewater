
rule i3ed_2bcb564f29a10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.2bcb564f29a10b16"
     cluster="i3ed.2bcb564f29a10b16"
     cluster_size="160"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue debris symmi"
     md5_hashes="['06dc869aba8dd5ed8e2ea944125ec5fe','0785c600b00f4b139e13b61bdd2de3ee','1ee2f5940546a2cf5b2ad848c6e5a76a']"

   strings:
      $hex_string = { 0355f48a45f88802ebbd8be55dc3cccccccccccccc558bec8b450850e864ffffff83c404eb098b4d0883c101894d088b55080fbe0285c0740f8b4d088a1180c2 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
