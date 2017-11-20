
rule k3f9_4b151b899ad30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.4b151b899ad30b32"
     cluster="k3f9.4b151b899ad30b32"
     cluster_size="1615"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shellini aueov wabot"
     md5_hashes="['002b35c48fce7bc091cd20ed45342966','00593456d67171d583c98b1dba8413c2','03d4b08cbbb4d47c275e7cae81e33d2e']"

   strings:
      $hex_string = { c1c9a84d452528d2a3adb63051e15cddbfe99ada6d86757d4cdfa562a648830d3324cb3a6a6755b256296e123118c8857fe59390069eb74a70e2cdfc5016bc76 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
