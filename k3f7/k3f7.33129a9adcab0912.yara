
rule k3f7_33129a9adcab0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.33129a9adcab0912"
     cluster="k3f7.33129a9adcab0912"
     cluster_size="32"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink script html"
     md5_hashes="['010acd54772cc713c9dcce0887992a64','06a6c044bc7f5ea09c8e3bedc61a5f4e','831db3b85816a3bcd3cd791b307a4bce']"

   strings:
      $hex_string = { 6e5f55532f616c6c2e6a73237866626d6c3d312661707049643d323230303534373034373033363731223b0d0a2020666a732e706172656e744e6f64652e696e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
