
rule k3e9_033c569bcb4ce315
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.033c569bcb4ce315"
     cluster="k3e9.033c569bcb4ce315"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genpack qukart backdoor"
     md5_hashes="['26194ba301ace6cb98a16d5ca3d61cf4','7615cb2b886430448c17607cd363e129','bc316ceb80464b064dd124a27ae8cb43']"

   strings:
      $hex_string = { 12e78bda2cdb7fa66e23f370795c9f59919944ce8a41d6d050d46d986b2446a08e0a4dd0417a0e9ed6183aa169dc7856161c855991a0ba393c62875be414efc9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
