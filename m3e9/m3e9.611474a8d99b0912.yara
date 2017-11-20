
rule m3e9_611474a8d99b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611474a8d99b0912"
     cluster="m3e9.611474a8d99b0912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['a7b04dd7c89af32b716911d51f37b6f0','ae63b95dd53589f4e79f7a432e777df5','b73d545bc2664f4d568fb0e7f01b7b84']"

   strings:
      $hex_string = { 27a7be483e9d388ebf3351b90dc0e2e30049874dfc30c8634d543528aaa7925a6a8875b497f41c9f464074e153596085698c341f9401a082b7e8f04beacd1e9e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
