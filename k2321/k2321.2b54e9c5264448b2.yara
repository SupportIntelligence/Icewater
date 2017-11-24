
rule k2321_2b54e9c5264448b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b54e9c5264448b2"
     cluster="k2321.2b54e9c5264448b2"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['3470799650d133f281db5c0ad7a1c4f7','7b1bfd92f0793715767108672c63eaee','de66b41c1f8412067781942b68877e22']"

   strings:
      $hex_string = { 905a6be648aeb8a9b13ce0bc96048968a57ffa1cc3c2240b4c00758a8e887b8b50b967a1ce8ce40f11c935e272ff20b9bd09279152f749776dcd37d21e16610e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
