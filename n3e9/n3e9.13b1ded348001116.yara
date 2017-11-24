
rule n3e9_13b1ded348001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13b1ded348001116"
     cluster="n3e9.13b1ded348001116"
     cluster_size="98"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa vilsel autorun"
     md5_hashes="['00006f1c4d83c437c7897dae0ae529d7','06723fd5b43937361509cbcaf9c23be4','572877c152adcdac27673d6d333ed979']"

   strings:
      $hex_string = { 0d0a3138323a49207761746368696e6720796f752064c58275676f2e204368636961c58262796d206dc3b37769c487207a20746f62c485200d0a3139303a2573 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
