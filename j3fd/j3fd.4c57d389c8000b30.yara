
rule j3fd_4c57d389c8000b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3fd.4c57d389c8000b30"
     cluster="j3fd.4c57d389c8000b30"
     cluster_size="85318"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="barys mogoogwi smha"
     md5_hashes="['000028e9dc22afdfe1ec13cc47efe78e','00004c01d8ef2e0cd113bb3859735f9e','000daf734214cd6edf8744e0c6bca7f2']"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
