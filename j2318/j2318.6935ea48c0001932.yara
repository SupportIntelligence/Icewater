
rule j2318_6935ea48c0001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2318.6935ea48c0001932"
     cluster="j2318.6935ea48c0001932"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html iframeref"
     md5_hashes="['489ac8501555c7b8dcf5db5a80bb724d','4cb75bc6c35cab6f7f1b3486806ed6be','e4db90bf89ac89e081e76ca2f80a8e2c']"

   strings:
      $hex_string = { 65743e3c2f666f6e743e3c736372697074206c616e67756167653d226a61766173637269707422207372633d22687474703a2f2f666174616c2e72752f616466 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
