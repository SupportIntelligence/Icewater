
rule k3e9_1b95ea48c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b95ea48c4000b16"
     cluster="k3e9.1b95ea48c4000b16"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['21de07763ab035203436887b76eee952','6ac96d5a175466270b932aada7aae6d0','f59c39ff606776807e5853f466fe22a6']"

   strings:
      $hex_string = { 30dd582d47b9373c45e44acda73d6d762a7bda85f8739e1c225ee9c9e7b34c5ba3340d1fa617d2b2085ade406c9326b7dfa5b6eccccbed893f57497d3e131233 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
