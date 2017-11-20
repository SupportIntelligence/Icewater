
rule m3f0_291f18e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.291f18e9c8800b12"
     cluster="m3f0.291f18e9c8800b12"
     cluster_size="17"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys kryptik dofoil"
     md5_hashes="['0b77a7596135c80cde77e0c79634d19e','10d277f6deb8efa79c27547950d10122','fbb5d0b3de5f26bf81a53a01bcb488db']"

   strings:
      $hex_string = { 6a840d3002bd60340ea9ef6f53a29b29186d20ce943b8cec69431b083f98e342c16c1758e8b74187c7ee36680a218696231183d351f304dca509ba3bc0d63167 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
