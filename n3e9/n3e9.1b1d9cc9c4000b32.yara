
rule n3e9_1b1d9cc9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1d9cc9c4000b32"
     cluster="n3e9.1b1d9cc9c4000b32"
     cluster_size="716"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['02098877defac57c9b60717b28c6f243','02106bb43a8a659a97bfd10422eb1dd4','0f7bd2e18cd05e14ccd23b206229a696']"

   strings:
      $hex_string = { aae571d7a76cfa65cfeff441567ab9435c774a5583acc6bf288045017f2b8e25183267e70f5bf05c9b920a0568a51b70d89ae5701c67692691ab9762e0466803 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
