
rule k3f7_13199699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.13199699c2200b12"
     cluster="k3f7.13199699c2200b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html blacoleref"
     md5_hashes="['14763a7ae7b47263c41fbfae7d5d69cc','23d2474b4cd2b2d4b03e8dad2976e61a','fe7a01689d5b1052c2ba500f944c571d']"

   strings:
      $hex_string = { 3e0d0a3c696d67207372633d222f2f706978656c2e7175616e7473657276652e636f6d2f706978656c2f702d39335063513142545670634d6b2e676966222062 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
