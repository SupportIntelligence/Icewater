
rule i3f4_4d669eb930d466b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3f4.4d669eb930d466b2"
     cluster="i3f4.4d669eb930d466b2"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="johnnie engine malicious"
     md5_hashes="['01446a00d1f608d740b9f67b977f561c','070882c38e95b3e861b988e9e9d9417e','c513f8cbaccf4f2e6131cc9b4751e9cb']"

   strings:
      $hex_string = { 3c72657175657374656450726976696c6567657320786d6c6e733d2275726e3a736368656d61732d6d6963726f736f66742d636f6d3a61736d2e7633223e0d0a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
