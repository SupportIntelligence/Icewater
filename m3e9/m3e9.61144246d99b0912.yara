
rule m3e9_61144246d99b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61144246d99b0912"
     cluster="m3e9.61144246d99b0912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack networm"
     md5_hashes="['4facc6bcaf7f6301d5772bfa1c3fdf59','a8ae37c5dde62fee20c8cccc13b726ea','b13a59ec04587afa29ee943547ba0f39']"

   strings:
      $hex_string = { 27a7be483e9d388ebf3351b90dc0e2e30049874dfc30c8634d543528aaa7925a6a8875b497f41c9f464074e153596085698c341f9401a082b7e8f04beacd1e9e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
