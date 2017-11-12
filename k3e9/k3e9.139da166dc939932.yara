import "hash"

rule k3e9_139da166dc939932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da166dc939932"
     cluster="k3e9.139da166dc939932"
     cluster_size="226 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['e5484822ca53cc74bc890efc60a77f5e', 'b4c9acfd9329c3a2ef5efe8a6bd45c32', 'dbd393faa02a73733f3535b41b29d4ab']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

