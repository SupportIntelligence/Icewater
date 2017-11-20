
rule j3eb_400153a202000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3eb.400153a202000000"
     cluster="j3eb.400153a202000000"
     cluster_size="42"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="crypt fjin rozena"
     md5_hashes="['0864d5599e930e47d2d9e5ceb2097e88','0965fd4919f9fdc6081073af54590d4d','60e2ddfcefb2d5a011beece43a40b352']"

   strings:
      $hex_string = { 0049c7c00030000048c7c2001000004833c9e82710000048c7c10010000048be4110004001000000488bf8f3a4ffd04833c9e8011000005041594c4f41443a00 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
