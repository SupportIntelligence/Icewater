
rule j3f7_69356a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.69356a48c0000932"
     cluster="j3f7.69356a48c0000932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html iframeref"
     md5_hashes="['24486ae65d861a4aa9189ed7f0fc649b','98c8e0a0bf2f385cf8573ab19312a00a','d67534aab840e020b747eb67dadd923c']"

   strings:
      $hex_string = { 6c65743e3c2f666f6e743e3c736372697074206c616e67756167653d226a61766173637269707422207372633d22687474703a2f2f666174616c2e72752f6164 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
