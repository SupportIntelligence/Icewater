
rule k3ef_219d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ef.219d6a48c0000b12"
     cluster="k3ef.219d6a48c0000b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet malicious chgt"
     md5_hashes="['091244080e8fb69c5c17572ed6f9ed05','28bca7726c145cb7eaf921a32955b48f','f66a0da15194c634900e3bb6c1bd0d94']"

   strings:
      $hex_string = { 5469746c652822446f744e65745a697020534658204172636869766522295d0a00005b617373656d626c793a2053797374656d2e5265666c656374696f6e2e41 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
