
rule k26bb_293b18609ed96996
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.293b18609ed96996"
     cluster="k26bb.293b18609ed96996"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore alphaeon malicious"
     md5_hashes="['f54bdfb797c82ccc1114b759ce750fb2c2004edd','3eb363a835d433a245401e37c00caa8e35688df0','4794d8d798d648ed60a776646a1e8ae079f8d131']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.293b18609ed96996"

   strings:
      $hex_string = { 5d6b6520abe95cd3f56eb5ade304dd23094061ae2ad239cfbcec237f9218e2a1a3c90bfb98d63b0ea691cc7155ee877e7781eb421d70dbb622f6a8600d438841 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
