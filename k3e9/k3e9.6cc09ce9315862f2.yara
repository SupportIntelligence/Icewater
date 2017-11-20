
rule k3e9_6cc09ce9315862f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6cc09ce9315862f2"
     cluster="k3e9.6cc09ce9315862f2"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch malicious mindspark"
     md5_hashes="['1141d90dfd0b807274bbdec3cb0bf8d5','2247615ad0c3e01423b667163c29bcec','f780eadb2a7c9ccd9e9ab146b3460671']"

   strings:
      $hex_string = { 7de341e7639a42d0e6acc80896ad1fb834e5c24b90f951dab5123c3f11552afd47716874ca936e655a2efe2338e0ba3be99985a754d26ad5057a0fa33d299cf7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
