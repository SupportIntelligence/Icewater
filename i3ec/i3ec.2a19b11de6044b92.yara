
rule i3ec_2a19b11de6044b92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.2a19b11de6044b92"
     cluster="i3ec.2a19b11de6044b92"
     cluster_size="95"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector infector malicious"
     md5_hashes="['02efca07bda3c6a57127cda21e231b79','059166af41a69966d258e99c971c7130','2d1160c78a922abecbb4eedb9b5b5a6b']"

   strings:
      $hex_string = { edeb797c8ffa4252a1626fab0c314f24233486fe6ed47b51f510fde762b14a4d6c086aee142dc2a54c2b5c6b11cb06e40cc41947919fa823ef7392e3db7e3925 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
