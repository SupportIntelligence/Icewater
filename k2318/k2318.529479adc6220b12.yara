
rule k2318_529479adc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.529479adc6220b12"
     cluster="k2318.529479adc6220b12"
     cluster_size="79"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['19e22003d13736cbcaa37b9c0182452813f49c31','6c30315a1fb7fcc0dab66bd4d63d8fec1e84b421','7dc701bb82a8816eb7c84ab58d5f07cd218e252d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.529479adc6220b12"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
