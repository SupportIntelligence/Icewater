import "hash"

rule k3e9_4b4626a4ce4e4c5a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ce4e4c5a"
     cluster="k3e9.4b4626a4ce4e4c5a"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c66d6eda39fd2d85a834c7b4790566e2', '58166f0df2683b8d89cff1e6b0e252a8', '58166f0df2683b8d89cff1e6b0e252a8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(38400,1280) == "8d605714fc674665af1478a4a862ce98"
}

