
rule o3e9_6130d4a2ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6130d4a2ca000b12"
     cluster="o3e9.6130d4a2ca000b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious kryptik filerepmalware"
     md5_hashes="['244ee4d2c94f8f6a167d5123fe4a3d1d','3d5b312a23d25b6be98dfe402a733aee','fc56c66b9efb2020ab30ef8a2bf8a29b']"

   strings:
      $hex_string = { 000000000f397e00123a7b01083784050f3a7e0f183e7d2b2a4b7d8f2a4e88fb1a3a74ff163063ff265093ff22488aff1f4384ff3a67a6d52d4d7f4229436d0d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
