
rule k3e9_15ba76b1c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15ba76b1c2200932"
     cluster="k3e9.15ba76b1c2200932"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mdeclass dangerousobject dldr"
     md5_hashes="['0639bc661952db9b010cd60525437ed4','1ebda270eb4990939a8781889d7be490','f010863a6e4abd8de4b68d47e3d1f2f0']"

   strings:
      $hex_string = { 4f9d8c725d1a81a2eb55f3b001ad3c71ac328f056b869a270032976a4dc964144b29bbc2d929b92eec63b3e1cf3f0b5690f8621b7eeba607e2de7f5e6d4038d4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
