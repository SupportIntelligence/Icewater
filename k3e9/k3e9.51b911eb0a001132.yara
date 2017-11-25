
rule k3e9_51b911eb0a001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b911eb0a001132"
     cluster="k3e9.51b911eb0a001132"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="madangel small madang"
     md5_hashes="['127318dcb31df5476ee514f819fb3bc2','1863b4d57831fd7c51526e0f8617ecc1','be524a5b76799621b2aff5988b09d59d']"

   strings:
      $hex_string = { 66813e4d5a78037901eb75ee0fb77e3c03fe8b6f7803ee8b5d2003de33c08bd683c304408b3b03fae80f00000047657450726f6341646472657373005e33c9b1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
