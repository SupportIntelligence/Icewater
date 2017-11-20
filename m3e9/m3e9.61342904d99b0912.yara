
rule m3e9_61342904d99b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61342904d99b0912"
     cluster="m3e9.61342904d99b0912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple malicious networm"
     md5_hashes="['0ccb6859e60266bce46a5a0b1fb27827','241b1621e1e3bd32c7a9480ce01431fa','caa578ffdad2f009e091f47af70c98dc']"

   strings:
      $hex_string = { 27a7be483e9d388ebf3351b90dc0e2e30049874dfc30c8634d543528aaa7925a6a8875b497f41c9f464074e153596085698c341f9401a082b7e8f04beacd1e9e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
