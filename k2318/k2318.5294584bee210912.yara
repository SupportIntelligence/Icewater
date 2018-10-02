
rule k2318_5294584bee210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5294584bee210912"
     cluster="k2318.5294584bee210912"
     cluster_size="99"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['fdd193c3a4ea17e454c2a7b91e706336740f7111','3171918e1d76a143faf3da5fd8133c9fb744bbc7','5a04cdf6e95018fbd9f8777533d9e23b3cff6153']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5294584bee210912"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
