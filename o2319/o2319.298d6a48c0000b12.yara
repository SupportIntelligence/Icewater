
rule o2319_298d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.298d6a48c0000b12"
     cluster="o2319.298d6a48c0000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer coinhive"
     md5_hashes="['126c059c3e9447460ec4442153748810d98b5bcd','886aa8908f73ce37580b0c9ec2ed20026d46f4c2','83b769b9a85b968ca9c85f9a63cfa0004191182a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.298d6a48c0000b12"

   strings:
      $hex_string = { 626c6f636b554928746869732e6470446976293b0a09097d0a0909242e6461746128746869732e5f6469616c6f67496e7075745b305d2c2050524f505f4e414d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
