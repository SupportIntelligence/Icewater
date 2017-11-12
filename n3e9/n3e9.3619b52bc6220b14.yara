import "hash"

rule n3e9_3619b52bc6220b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3619b52bc6220b14"
     cluster="n3e9.3619b52bc6220b14"
     cluster_size="2202 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="auslogics malicious silentinstaller"
     md5_hashes="['1658ef97f8d4e95aad386b0f0f503ff8', '0ccd4ceb04174592b43778b357618c55', '20e95263c5f601311c14235b0d2a9f1f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(350208,1024) == "538363a4ea0fef632324399081c25270"
}

