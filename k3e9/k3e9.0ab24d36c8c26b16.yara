
rule k3e9_0ab24d36c8c26b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0ab24d36c8c26b16"
     cluster="k3e9.0ab24d36c8c26b16"
     cluster_size="357"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot ramnit krap"
     md5_hashes="['004b0a08a2f14eb007e53249b223c57e','0059fcd77c4820a4957099ea5744a642','0e56f8a23222c470d025f7fde5341893']"

   strings:
      $hex_string = { ca742a44ada00401874695820fb051654c1299e819aa1000d2defa7f6b0e9bd926033c135d0df4767a9a75c240e07c174bb49dd98f1ee4cf89c78bda2ff55b32 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
