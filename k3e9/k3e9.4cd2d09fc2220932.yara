
rule k3e9_4cd2d09fc2220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4cd2d09fc2220932"
     cluster="k3e9.4cd2d09fc2220932"
     cluster_size="2203"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre ipatre kryptik"
     md5_hashes="['002b817879a7f416c833eadafb36bccf','002ce59951efa19e95284f3ddb0f3b26','01bf76855e1156db2daa8df7793560bc']"

   strings:
      $hex_string = { d4430652b2231ffe610aa9738db1ca563532f44aab73a9cb5f26b6fdcb7e86bd44f88fe2420964f5772e8251c622bd4cfce92a67fe6112a153c9348757a6b994 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
