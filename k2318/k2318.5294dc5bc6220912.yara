
rule k2318_5294dc5bc6220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5294dc5bc6220912"
     cluster="k2318.5294dc5bc6220912"
     cluster_size="697"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['10ebe69814c453f15644cb9089d5828c145a4ecf','147aea173925de7ff827e276f499923a06160865','eaea795f17998f8aefaf59b0bb3dd00bab7da94d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5294dc5bc6220912"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
