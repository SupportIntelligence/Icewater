import "hash"

rule n3e7_292b8e4215c66b96
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.292b8e4215c66b96"
     cluster="n3e7.292b8e4215c66b96"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="guagua porntool tool"
     md5_hashes="['e25af72d75bae96d382981ffcddc6654', '35d16572ce805f8b0980e61dbee08417', '35d16572ce805f8b0980e61dbee08417']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(367616,1024) == "ea667db5382b916852f7bb0ce3a31cc8"
}

