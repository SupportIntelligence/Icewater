
rule i3e9_56e9171682000116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.56e9171682000116"
     cluster="i3e9.56e9171682000116"
     cluster_size="259"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector aaavjfmi malicious"
     md5_hashes="['01f8e7ee5ffd6e9ac41ac86354214c14','02f646511504170fc25b778ea17da263','130e787e325bd848fbc220d8397105fc']"

   strings:
      $hex_string = { edeb797c8ffa4252a1626fab0c314f24233486fe6ed47b51f510fde762b14a4d6c086aee142dc2a54c2b5c6b11cb06e40cc41947919fa823ef7392e3db7e3925 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
