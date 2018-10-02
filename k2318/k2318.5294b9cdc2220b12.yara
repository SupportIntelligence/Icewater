
rule k2318_5294b9cdc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5294b9cdc2220b12"
     cluster="k2318.5294b9cdc2220b12"
     cluster_size="287"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['3752898adb8f549ece7b19fc4688ef616d6e52ce','9a34d6b0744a14904ac2e3289e4e11f45e0213f3','8e0b6d784affee21dfd1182229cc0d2c0b522379']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5294b9cdc2220b12"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
