
rule n3e9_251d94c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.251d94c9cc000b32"
     cluster="n3e9.251d94c9cc000b32"
     cluster_size="473"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['003adee875af401fbad1d8ab9e3bec38','00c9439202a7fe0e1180b5abee671a92','13f1070c2cb8cece12c6b7460019c90f']"

   strings:
      $hex_string = { 7711e81e84b48219b52d56bdf99525b02a4e37aee6b14fdf678e04585ed8f1302be1830daea4abac9d84c1ad5043833b79d4c5d8e761420cb3b119d716c7a7b1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
