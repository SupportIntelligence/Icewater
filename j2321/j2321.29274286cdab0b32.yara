
rule j2321_29274286cdab0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.29274286cdab0b32"
     cluster="j2321.29274286cdab0b32"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre generickd trojandownloader"
     md5_hashes="['1c69da39c3b6e305ea2784bf4f2f2381','20857c8f67b89ed170c77f0fbdcd0506','fe787055730b2ab5f45a0721ad4866e0']"

   strings:
      $hex_string = { 12b537a0cf529a1eef95715166b98514e1e674dc483f0beb66924f45b032bd889619ac6c3ca7208c7abf068a6a8cc66b83c0a85327c0d413d861f7759cd96f38 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
