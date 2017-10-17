import "hash"

rule n3fd_4eeb4cbb51e956c6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.4eeb4cbb51e956c6"
     cluster="n3fd.4eeb4cbb51e956c6"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="expiro xpiro allinone"
     md5_hashes="['b46756347a89107e126801c928615b2c', 'aa16329a2f5be8ce14bc50447c4a9ff3', 'c550c7f809e6f249aa2062edf02b4d8a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(774144,1024) == "85e4cef5db11c0c4d93ea2c06234513d"
}

