
rule i3e9_46e9171682000116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.46e9171682000116"
     cluster="i3e9.46e9171682000116"
     cluster_size="408"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector aaavjfmi malicious"
     md5_hashes="['003adb6f500bfe49a288984181dd9166','00df165254624038c7314fbae6f190c2','0a3fadba11a425a613a7fb377b83fd9a']"

   strings:
      $hex_string = { edeb797c8ffa4252a1626fab0c314f24233486fe6ed47b51f510fde762b14a4d6c086aee142dc2a54c2b5c6b11cb06e40cc41947919fa823ef7392e3db7e3925 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
