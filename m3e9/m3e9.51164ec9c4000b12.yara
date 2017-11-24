
rule m3e9_51164ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.51164ec9c4000b12"
     cluster="m3e9.51164ec9c4000b12"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbna pronny"
     md5_hashes="['09d1cddec7c896a07863e68a40015905','1c9e32ab6fab844e25265078a4f490fb','de5dc000aa9acca08c6024d6e76b5713']"

   strings:
      $hex_string = { 082d366ec3747252b6838a8a150248ccf1f4f4f3f6cb472800000003858585b1c3c3c2c5cdd8c53d2b2e2e2d2a080829292e3d6fb7777452725353530d0560cc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
