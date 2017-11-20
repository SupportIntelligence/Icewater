
rule k2321_0ae89c542e6f48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ae89c542e6f48ba"
     cluster="k2321.0ae89c542e6f48ba"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['22a4957675d8320b31f5f42501661315','43df132cfbbd503801ef941ec048c21b','fcb29a046fb4837db3bb241b237c393a']"

   strings:
      $hex_string = { 70bb29794bf7667d0e3ed5b0b8e7c3cf2d933cd7e1d19b118ce09ce4836384a937df042c97af013e959ab3756ceefae65cef7465d8c8155b228a5ff4c234f672 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
