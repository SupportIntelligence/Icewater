
rule k3e9_2a664a504a9348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2a664a504a9348ba"
     cluster="k3e9.2a664a504a9348ba"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy flmp"
     md5_hashes="['4a03f321825714593610bd0d80e0bbba','9fdc1334c2f293f1012b30ad3e17e533','e6077025d7263f0e88d2ffacce03ff7f']"

   strings:
      $hex_string = { 9f458d0997baf162d5e97910752c4485c7a20592cc91c4418a81fc7e005c15d0ec3733cb0b70fa9430d11150df8464abd2834f4d06f86682caa676807d995413 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
