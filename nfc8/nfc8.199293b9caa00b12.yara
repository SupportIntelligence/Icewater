
rule nfc8_199293b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.199293b9caa00b12"
     cluster="nfc8.199293b9caa00b12"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker asacub"
     md5_hashes="['b52c0b2d0b676a7fedd3cf318726be9950d72ea1','995df4e757d765a154fdd8b1398377ad0a577230','7c972e15454b974b0e4b40d4349a4170cac2055a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.199293b9caa00b12"

   strings:
      $hex_string = { d9d1ea83dc6ed829ecfdd622e6664ecd2a6c94bc216c56dbe7a9b860ab1bb3317ea68d8ee988f1e4901f5225ef59b604a3d22fb09dfca2ce98a575541196134b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
