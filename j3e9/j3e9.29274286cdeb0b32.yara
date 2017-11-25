
rule j3e9_29274286cdeb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.29274286cdeb0b32"
     cluster="j3e9.29274286cdeb0b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader generickd"
     md5_hashes="['349983f1ab64eae23acba3b21f62c952','559c3b6ff8a448868e163566b54ac22e','fe756a0162d626ae8c310ff0d3abadae']"

   strings:
      $hex_string = { 12b537a0cf529a1eef95715166b98514e1e674dc483f0beb66924f45b032bd889619ac6c3ca7208c7abf068a6a8cc66b83c0a85327c0d413d861f7759cd96f38 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
