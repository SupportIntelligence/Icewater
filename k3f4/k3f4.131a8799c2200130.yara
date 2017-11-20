
rule k3f4_131a8799c2200130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.131a8799c2200130"
     cluster="k3f4.131a8799c2200130"
     cluster_size="66"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor advml"
     md5_hashes="['2520944baf0b10879e1782772558765a','2aa503f958ba5e603e9222c75f510ec1','94a57d0e443e911171845112b7a4f327']"

   strings:
      $hex_string = { 312e302e302e3022206e616d653d224d794170706c69636174696f6e2e617070222f3e0d0a20203c7472757374496e666f20786d6c6e733d2275726e3a736368 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
