
rule n3f0_0e931d65ddbb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.0e931d65ddbb1912"
     cluster="n3f0.0e931d65ddbb1912"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira symmi malicious"
     md5_hashes="['6ceb6066c6c4fd0a437ff1c19cd65f22','a7882bdcb7911e30bbdb59e537f916f5','ee712d4d9f261cd05d8516e1b7ae2f63']"

   strings:
      $hex_string = { 22f3070912643063cb9a2028b853f17df00f87aee8682cc0b100815b59261e1a9056c8b9c171f243350e4d69e9f59e6a32fdd2134a9f0bd1418cf40a7c7ba180 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
