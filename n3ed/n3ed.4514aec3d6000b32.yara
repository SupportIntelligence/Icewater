
rule n3ed_4514aec3d6000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.4514aec3d6000b32"
     cluster="n3ed.4514aec3d6000b32"
     cluster_size="205"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox unwanted yontoo"
     md5_hashes="['013575bcc192f91a1d7227ee593eba27','02abe155132ade6f0115e4fa46e119c0','17d1156250f02653e8111c36f298ab08']"

   strings:
      $hex_string = { 05200000636d7078636867000000000000000000006804078b680000002405070000040000fc0000210000000a0000000000000002000000012000006c737300 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
