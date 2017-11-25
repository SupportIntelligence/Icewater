
rule m3f7_493c3841c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.493c3841c8000912"
     cluster="m3f7.493c3841c8000912"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['091cf4664ce9516f0a80f80c0f729c51','13365dfd01bcc3b0bd62191d19acb551','a2e1fda3edeba3d19f468a54b28e9c73']"

   strings:
      $hex_string = { 722e5f506f707570436f6e66696728646f63756d656e742e676574456c656d656e7442794964282248544d4c372229293b27207461726765743d27636f6e6669 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
