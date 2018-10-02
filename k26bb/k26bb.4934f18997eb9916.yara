
rule k26bb_4934f18997eb9916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.4934f18997eb9916"
     cluster="k26bb.4934f18997eb9916"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious virut susp"
     md5_hashes="['78b51bb8b01eaf8352dab36f675202c07d401dfa','051896b8f25a232eba1da6afb911c147a3cb7548','d582ec18a99cbf7855ed93f3bbd504612f974626']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.4934f18997eb9916"

   strings:
      $hex_string = { 12f6853c74e6afd647b5faf0ca90d7436468ce92a73270604c8d0525840bb86603c427785c81736f4994631a1522eb7f04612c8dbbc06a5048bc0fb1c21b4182 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
