import "hash"

rule o3e9_15b2cc6b14796cb1
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.15b2cc6b14796cb1"
     cluster="o3e9.15b2cc6b14796cb1"
     cluster_size="148 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['86c819fc90ba72d0e998dce7bcd04672', 'fc7a024ab621f18e8669e2c4bb96b95b', '4ff52866bc90813de4eb1fb9a4da8d23']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3109774,1026) == "bc1d09a2a720023e809c0e4bc6e1d73a"
}

