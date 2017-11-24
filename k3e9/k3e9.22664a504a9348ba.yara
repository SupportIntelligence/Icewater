
rule k3e9_22664a504a9348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.22664a504a9348ba"
     cluster="k3e9.22664a504a9348ba"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy flmp"
     md5_hashes="['018a6bfb55227f5da855fe3ede48a270','0ac2b7658ac3403387fa6c201739a2ce','bf4fef2296095be7de49209b434bdac8']"

   strings:
      $hex_string = { 9f458d0997baf162d5e97910752c4485c7a20592cc91c4418a81fc7e005c15d0ec3733cb0b70fa9430d11150df8464abd2834f4d06f86682caa676807d995413 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
