
rule i3ed_2bcb564f2aa10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.2bcb564f2aa10b16"
     cluster="i3ed.2bcb564f2aa10b16"
     cluster_size="19"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris gamarue zusy"
     md5_hashes="['1e3ff641c34e3de35c1873dbef9a2ff1','2f02c5cb18bc0fa3ebdcae1b54ad0ae7','e96dce763fa86edc01a73a6efafe0773']"

   strings:
      $hex_string = { 0355f48a45f88802ebbd8be55dc3cccccccccccccc558bec8b450850e864ffffff83c404eb098b4d0883c101894d088b55080fbe0285c0740f8b4d088a1180c2 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
