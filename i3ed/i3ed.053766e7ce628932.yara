
rule i3ed_053766e7ce628932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.053766e7ce628932"
     cluster="i3ed.053766e7ce628932"
     cluster_size="526"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris gamarue generickdz"
     md5_hashes="['006fb1d3197ae0a24bf750a89164bd94','009c8897379d5d51f1b40d500c3c0c9b','0b2b3759db78de64201a20ba2b5a3ed4']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a15030001083ee04ebea50ff151420001083255030001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
