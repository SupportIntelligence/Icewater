
rule k3e9_291df3a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291df3a9c8000932"
     cluster="k3e9.291df3a9c8000932"
     cluster_size="81"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['05ccfe154d04a80c480d378552cf9880','09e7aed757540406b60526e2c00f7cae','5f7c70f0a696046a8942ad43464a1730']"

   strings:
      $hex_string = { 21ebbc0395bc051a9ba03365500f1ac00b90ff8817a180e24fdd27260914fc3510d0d61d3c480019b6a80cba414da3917fd3ed690102af49a6e4f3b815ca772c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
