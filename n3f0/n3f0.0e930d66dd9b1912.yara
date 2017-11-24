
rule n3f0_0e930d66dd9b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.0e930d66dd9b1912"
     cluster="n3f0.0e930d66dd9b1912"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira symmi malicious"
     md5_hashes="['1fac97bd67b3883cd0d4f2ebe3053e5d','258487691a592ffe5bc23558b9ee202c','f75e2fec8fa0242215d3947c1db2ae83']"

   strings:
      $hex_string = { 22f3070912643063cb9a2028b853f17df00f87aee8682cc0b100815b59261e1a9056c8b9c171f243350e4d69e9f59e6a32fdd2134a9f0bd1418cf40a7c7ba180 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
