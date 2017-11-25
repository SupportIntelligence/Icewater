
rule k3f7_33129a8b969b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.33129a8b969b0912"
     cluster="k3f7.33129a8b969b0912"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['449897ec00c93de30f134727c5343b72','595cc2022551059e6064cbded09e8cd0','caed7f6fdf3184c360a872661d3f869d']"

   strings:
      $hex_string = { 3e0d0a3c696d67207372633d222f2f706978656c2e7175616e7473657276652e636f6d2f706978656c2f702d39335063513142545670634d6b2e676966222062 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
