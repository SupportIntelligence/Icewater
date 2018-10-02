
rule n26bb_5572d5a3ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.5572d5a3ca000b12"
     cluster="n26bb.5572d5a3ca000b12"
     cluster_size="1906"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy spyware canp"
     md5_hashes="['431fc09dfc8dee71f624309d8c074ab4b6d97724','638e66c76b0963255f93b77fc12ed4e265efc142','47bf59371ec529e994882f6c411f85533f63860a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.5572d5a3ca000b12"

   strings:
      $hex_string = { 4b20eb07a88074188b4b2485c976118b4fe48d44241050565251ff15483040008b54241833c04583c7288b1a668b43063be80f8c6dffffff5f5e5d5b59c39090 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
