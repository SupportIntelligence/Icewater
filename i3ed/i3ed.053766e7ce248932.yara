import "hash"

rule i3ed_053766e7ce248932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.053766e7ce248932"
     cluster="i3ed.053766e7ce248932"
     cluster_size="549"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris symmi gamarue"
     md5_hashes="['00a7938a51b47a6f0983092615bbe354','012926edf0f4956895264423d0ba2ca1','0c01ab5d1c9becba98e65ddfd186ded7']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "73238df589b72e3187ccc4625eb01234"
}

