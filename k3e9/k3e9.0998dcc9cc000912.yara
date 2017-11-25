
rule k3e9_0998dcc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0998dcc9cc000912"
     cluster="k3e9.0998dcc9cc000912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['41f9e42131a93d4356a907880df46114','448b8849e3a1b56d69dab3ddef3dfb35','d5e26c25515b8947e177c616a065e9c0']"

   strings:
      $hex_string = { cbcd20fbba54bd7e09fed33c60ad375becdb744bb438565e0af0b3dc8215b9ab34451cbb5ac3e52c67657a30ccd45c90e99f6bb73f6435673278245263de5607 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
