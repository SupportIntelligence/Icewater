
rule k3f4_034e8799c2200330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.034e8799c2200330"
     cluster="k3f4.034e8799c2200330"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor bkdr"
     md5_hashes="['32d29d071ec81c70cbadc797c2689446','3cc8b2f0a64de5b4194bddccfe74fa0d','bfe94de3bef974b19f82944ef649836f']"

   strings:
      $hex_string = { 312e302e302e3022206e616d653d224d794170706c69636174696f6e2e617070222f3e0d0a20203c7472757374496e666f20786d6c6e733d2275726e3a736368 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
