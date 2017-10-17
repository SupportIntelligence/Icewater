import "hash"

rule n3e9_496452a88d0a6192
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.496452a88d0a6192"
     cluster="n3e9.496452a88d0a6192"
     cluster_size="84 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="airadinstaller airinstaller bundler"
     md5_hashes="['15791b118fe7029865c3c8fb86762f59', '33cbbe3dcfc9fd38372d7f4577be03f7', '34657856db0b8b5770f5f9160e42e202']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(695808,1024) == "9d65e4e2abb9b59154c28588626092dd"
}

