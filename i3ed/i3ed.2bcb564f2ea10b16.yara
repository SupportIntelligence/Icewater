
rule i3ed_2bcb564f2ea10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.2bcb564f2ea10b16"
     cluster="i3ed.2bcb564f2ea10b16"
     cluster_size="59"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue debris zusy"
     md5_hashes="['05c31864fa6b43dde7582b2ee11e2ffa','07273929895137a787bd5f1d6e2a22bc','4f1f4694197193d904f41b0f6b242891']"

   strings:
      $hex_string = { 0355f48a45f88802ebbd8be55dc3cccccccccccccc558bec8b450850e864ffffff83c404eb098b4d0883c101894d088b55080fbe0285c0740f8b4d088a1180c2 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
