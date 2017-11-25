
rule k3e9_09146a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.09146a49c0000b32"
     cluster="k3e9.09146a49c0000b32"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre bublik jqvu"
     md5_hashes="['31ad0650886ef6e2778f9b6174575c66','360d66a969ac49ffd2f6c96b0bbdbc52','f8d63cd87a71c92822b8b4c51a5d502a']"

   strings:
      $hex_string = { 967a4a14f53ee215bb64e056a94e8a8665ef871a4db23a69cd60a657f495499ae49094f821339155fab3635531747dc367cb43dd848298c44404f1e724c2ccd1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
