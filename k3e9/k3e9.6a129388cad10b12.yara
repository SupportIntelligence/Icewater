
rule k3e9_6a129388cad10b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a129388cad10b12"
     cluster="k3e9.6a129388cad10b12"
     cluster_size="85"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bundler yantai nsismod"
     md5_hashes="['125678a807f6997fc8f7f24167b777ca','1506058c8307d8424a0cc11a020b3eb5','3cbf5874aa2f77862835b47792dc9183']"

   strings:
      $hex_string = { e9a1feffff5f5e5d5b59c38b4c24048b811408000085c07c2b568d7041c1e6055703f18d78018b0685c07410837efcff750a50ff150c91400083260083ee204f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
