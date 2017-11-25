
rule n3e9_2b54caabc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b54caabc6220b32"
     cluster="n3e9.2b54caabc6220b32"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious bqqso"
     md5_hashes="['706158c88e3d89efb347b94ea84f616a','9d94863498208bf20c2e768936e909dd','d8bd030a12b13f91d43e703ab2c7a737']"

   strings:
      $hex_string = { 004d006f006e00030054007500650010002500730020002800250073002c0020006c0069006e00650020002500640029000e0041006200730074007200610063 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
