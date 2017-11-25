
rule i3ec_2a39b11de6044392
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.2a39b11de6044392"
     cluster="i3ec.2a39b11de6044392"
     cluster_size="172"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector infector malicious"
     md5_hashes="['0651838c553ef9d75f999d0fd99b516f','06f09c3a933685b58c4ec9135d66d40b','192d16ce8d68a4b765b966352384c47b']"

   strings:
      $hex_string = { edeb797c8ffa4252a1626fab0c314f24233486fe6ed47b51f510fde762b14a4d6c086aee142dc2a54c2b5c6b11cb06e40cc41947919fa823ef7392e3db7e3925 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
