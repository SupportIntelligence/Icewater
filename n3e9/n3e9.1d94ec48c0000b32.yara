
rule n3e9_1d94ec48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1d94ec48c0000b32"
     cluster="n3e9.1d94ec48c0000b32"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader waski"
     md5_hashes="['1b7a4465f131130af32ee01f6f4ac7f6','50d6ca5e13010aec6112236ab198636b','d03dbfd853a26fe07e4b3ae588eddfa6']"

   strings:
      $hex_string = { fb73ac58ee8475904ffd990d4d39962ea52b2cd0cb741bf8c9fe9c1c7a3eecebc427be655b5186d59b5d80795318664c8f013852f3a4d103ef3afa3502f5478d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
