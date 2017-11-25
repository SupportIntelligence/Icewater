
rule k3f7_3713956cd6d30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.3713956cd6d30b12"
     cluster="k3f7.3713956cd6d30b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html redirector"
     md5_hashes="['87171eff2a154f9d3debd1ccec349570','8d86d0d7752d6300da41e36f9eeb9f6a','dfbe3412d8cedbc7f7e2c567cbc8abe2']"

   strings:
      $hex_string = { 3e3c696d67207372633d22696d616765732f706978656c5f7472616e732e6769662220626f726465723d22302220616c743d22222077696474683d2231303025 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
