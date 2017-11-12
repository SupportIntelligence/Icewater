import "hash"

rule o3ed_539c168dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539c168dc6220b12"
     cluster="o3ed.539c168dc6220b12"
     cluster_size="914 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['0328e719b5e8f4bde0ae369286114887', 'a019ad7b96a35191a3b7553e65f4b247', 'a9d2c953b07187f1614ef4f1383c6b2a']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1646592,1024) == "212ae30c5ded1d85044a3327f766f3a2"
}

