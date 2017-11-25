
rule k3f7_3312da1adcab0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.3312da1adcab0912"
     cluster="k3f7.3312da1adcab0912"
     cluster_size="30"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html redirector"
     md5_hashes="['05a3ae5a2ef5d2f9328149c9ef34dbb3','05c433926dbeb36cb03deb582448d4c6','7b7a39d7f52b2a5ced6c177fc057f43c']"

   strings:
      $hex_string = { 656e5f55532f616c6c2e6a73237866626d6c3d312661707049643d323230303534373034373033363731223b0d0a2020666a732e706172656e744e6f64652e69 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
