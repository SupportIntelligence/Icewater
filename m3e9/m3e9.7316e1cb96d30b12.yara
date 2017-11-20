
rule m3e9_7316e1cb96d30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7316e1cb96d30b12"
     cluster="m3e9.7316e1cb96d30b12"
     cluster_size="160"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt diple"
     md5_hashes="['00a9d839ef83fd73d62a8b4a5b19c54f','0482c8bb94c12e2edd3ee108750a6cda','6e3ec877f71dbcbdb6dbb81dec7bfdec']"

   strings:
      $hex_string = { dad6cacbbfb692958c17193cb9d5daf6f6f3d8c84b25000000252a32323f6dcaf2f2f6f9d74931303f49b5bcd7f0f2f2d8d5c1c0beb87a9491791a1f61d4f6da }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
