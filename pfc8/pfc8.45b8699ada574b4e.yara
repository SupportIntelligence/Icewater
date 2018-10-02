
rule pfc8_45b8699ada574b4e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.45b8699ada574b4e"
     cluster="pfc8.45b8699ada574b4e"
     cluster_size="95"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp airpush andr"
     md5_hashes="['a18f5c24681f28c2db33c9f481bab09e1d465392','1efda06e127479355976878d5abfebe941b74823','e48f379023312d7e520b83091f11a53b5c2327fd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.45b8699ada574b4e"

   strings:
      $hex_string = { ae23870fe435e8af4f9165b909a7db0d005d80f7ff0418979bb2f38eaa3e29490b3abc4a48772abd41c8ceb6368642c1c2639ef5e1e246596beacd2d5a93d85c }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
