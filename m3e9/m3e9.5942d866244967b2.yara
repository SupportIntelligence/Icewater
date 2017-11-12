import "hash"

rule m3e9_5942d866244967b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5942d866244967b2"
     cluster="m3e9.5942d866244967b2"
     cluster_size="303 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef autorun"
     md5_hashes="['e5262126ea6ddef563e41001e58503ae', 'e3a62a130dfc9ef5c4646dcd3231518b', 'c201f087be7464e66064b6607a5dfbf5']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(226304,1024) == "ed013d01ed5bbf888562ea75e2e0bae5"
}

