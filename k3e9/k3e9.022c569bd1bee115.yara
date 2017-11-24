
rule k3e9_022c569bd1bee115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.022c569bd1bee115"
     cluster="k3e9.022c569bd1bee115"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart backdoor berbew"
     md5_hashes="['2b63187081600794acff8b151fe51c31','b817bbd63cdb3f8533815190ee4f3e93','fcdd0d8d4d6d1289be531cca85b1d627']"

   strings:
      $hex_string = { 12e78bda2cdb7fa66e23f370795c9f59919944ce8a41d6d050d46d986b2446a08e0a4dd0417a0e9ed6183aa169dc7856161c855991a0ba393c62875be414efc9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
