
rule m3e9_6134c3a4b13b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6134c3a4b13b0912"
     cluster="m3e9.6134c3a4b13b0912"
     cluster_size="42"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['00b42baea9024afbbdd6842879edcd4d','131243df36cd0c960754a31ca371179d','afb35d8ca2dab4e15e5add9e4f6a468d']"

   strings:
      $hex_string = { 27a7be483e9d388ebf3351b90dc0e2e30049874dfc30c8634d543528aaa7925a6a8875b497f41c9f464074e153596085698c341f9401a082b7e8f04beacd1e9e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
