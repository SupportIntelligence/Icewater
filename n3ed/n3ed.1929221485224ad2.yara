
rule n3ed_1929221485224ad2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1929221485224ad2"
     cluster="n3ed.1929221485224ad2"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy delf malicious"
     md5_hashes="['0a3d2aa392d6e773e9d0e1ea74f39bf9','a0a7b38f601fc0e6bd9ce0d229d79d2f','fc793e7a771cc03d76ed6de7c5d2ce84']"

   strings:
      $hex_string = { bda220e0774c8beb06397872659cc27ff215ea758f17cd5be3ef896cdfa8ff1b13d76242e58398d90f3248450e1d768ebc84b757d449f5909f7e643ef6a74492 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
