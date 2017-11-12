import "hash"

rule k3e9_36c7ea48c0010b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.36c7ea48c0010b12"
     cluster="k3e9.36c7ea48c0010b12"
     cluster_size="428 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre bublik daytre"
     md5_hashes="['9456c2410bfe2d888e6215fac4a936a4', '0b33a8048ba937113d421a5475dce3a7', 'cfc464b48915444a675155a6aecf3842']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8192,1280) == "78432868754d78118874cd5bd53e16e3"
}

