
rule n3e9_439dea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.439dea48c0000b12"
     cluster="n3e9.439dea48c0000b12"
     cluster_size="263"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef jorik"
     md5_hashes="['0106fa352178103cd13ebfaf4c863283','018e90e15f143f4c7857b36e29502c7b','2c45d21f6d00b26f0a2ef21c1da5039f']"

   strings:
      $hex_string = { 000000833dd0f8430000751b68d0f84300687c6d4000e8e48cfcffc7851cfaffffd0f84300eb0ac7851cfaffffd0f843008b851cfaffff8b008985b8fcffff8d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
