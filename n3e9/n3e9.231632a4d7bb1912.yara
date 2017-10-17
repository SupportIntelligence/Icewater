import "hash"

rule n3e9_231632a4d7bb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.231632a4d7bb1912"
     cluster="n3e9.231632a4d7bb1912"
     cluster_size="42 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="dangeroussig malicious adload"
     md5_hashes="['c76b26165f576b378d6a8ea90208f6f0', '0b73ea7a5bf78fd527a4f3ff9e099b30', '85800760093dc41f1216f54621cc47a1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(519168,1024) == "034dc94f9be5fd2c187e8adf3cdb28e4"
}

