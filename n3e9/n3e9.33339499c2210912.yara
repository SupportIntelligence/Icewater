import "hash"

rule n3e9_33339499c2210912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.33339499c2210912"
     cluster="n3e9.33339499c2210912"
     cluster_size="28347 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="downloadguide bundler downloaderguide"
     md5_hashes="['01ca27747fd85564a1f9cd28cff31655', '01532013e4b2d379bde67db06bc6ff54', '01b1ad11e5a502e9a9cd9cfcdc07270a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(510976,1024) == "fa716579da0995e1f72ab2b907b2339d"
}

