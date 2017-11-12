import "hash"

rule k400_0c524f2b15b3f332
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k400.0c524f2b15b3f332"
     cluster="k400.0c524f2b15b3f332"
     cluster_size="63 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor hupigon"
     md5_hashes="['acdf595055c4c541458ea477de0c891f', 'a54676255140240ac381802b582464db', 'a66bed83f4aed2143cf045383331ee01']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(30208,1024) == "665eef8a7409a541d6eda42790bc4d14"
}

