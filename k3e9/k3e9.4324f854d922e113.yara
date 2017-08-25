import "hash"

rule k3e9_4324f854d922e113
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f854d922e113"
     cluster="k3e9.4324f854d922e113"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c39938468b377b8053c3732aff640192', 'ad3812951ee1df4224ea00d2f37adf4e', 'a90246f26fec616b288e20e1b583cc23']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20992,256) == "a5658a555b991c738a328ec7df4c12bc"
}

