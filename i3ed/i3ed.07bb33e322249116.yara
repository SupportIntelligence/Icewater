
rule i3ed_07bb33e322249116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.07bb33e322249116"
     cluster="i3ed.07bb33e322249116"
     cluster_size="60"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue symmi bundpil"
     md5_hashes="['001835335830fe58f4e77b8ba5d7c8eb','0ac8ed47d5aea66ac0b82446c36b8b66','3e7e71047b4625461965f62525101dcb']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a13832001083ee04ebea50ff151c20001083253832001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
