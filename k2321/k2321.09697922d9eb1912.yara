
rule k2321_09697922d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09697922d9eb1912"
     cluster="k2321.09697922d9eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['146087af347d703c598ec02e76127731','146fc3ea9a5b0beb4f707c4aeef214dd','e0e3cae139575fa82cfaa9e0a426731d']"

   strings:
      $hex_string = { 1441da2fcb5fc5b06cef31e750b77be42b607d9dd9898e169a40e576f92e064eaf3e660f7e7bf20794341001512849b5865469f5a54e2658211e7a3c26d17f47 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
