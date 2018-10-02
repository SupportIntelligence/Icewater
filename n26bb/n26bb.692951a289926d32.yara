
rule n26bb_692951a289926d32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.692951a289926d32"
     cluster="n26bb.692951a289926d32"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ddzu malicious backdoor"
     md5_hashes="['330eeffe5f63a4853969d05ca685159c01336150','a7d3e78c575629ed75629bc7c6f8d5309d76320f','16ced5bd775a9443c209518b27a1b8086f64a4a7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.692951a289926d32"

   strings:
      $hex_string = { 44b9a48c710be83e3d2c6ad920cbf462123fb818bbdfbc8286bd5efdf56f14a6b2e7919f34dcfae245107081cc9a76b0b60994ac8043a32a5a388d7fc3079ba0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
