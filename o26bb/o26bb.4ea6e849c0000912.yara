
rule o26bb_4ea6e849c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4ea6e849c0000912"
     cluster="o26bb.4ea6e849c0000912"
     cluster_size="133"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler dealply malicious"
     md5_hashes="['ae2870429e6a83b68f668e11867c0a1a1e46f8b4','d12de3e7ba5e9532da910c9a4c48ca6b23986cee','898b3f58de987970f1c4b0126d80df4453373b1c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4ea6e849c0000912"

   strings:
      $hex_string = { 88c5d26008370002837b9bd067c722606a2da2e25815cc70771309b4a8ff63abe89e1d12749d23508a7581d97ea6cbd074490dbd013da34b097d32c38d40009f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
