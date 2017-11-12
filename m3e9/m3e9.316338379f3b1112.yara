
rule m3e9_316338379f3b1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338379f3b1112"
     cluster="m3e9.316338379f3b1112"
     cluster_size="188"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['097899f599319513ef2906d93d66807b','17effe2e6c79258b903ff59f1925ef0c','62d09b2d2a053089b1e758012bd2fa40']"

   strings:
      $hex_string = { fbabbb14d4f2da13eaeec61710f04291340b7675df7f0bd1c26f09d9e32eb9fea00590fa2feb3f64c4d77f72a710d67f782188803b4192c2359c1dc6d607c325 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
