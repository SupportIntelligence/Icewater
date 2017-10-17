import "hash"

rule n3e9_4998a16fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4998a16fc6220b12"
     cluster="n3e9.4998a16fc6220b12"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="krypt loadmoney cryptor"
     md5_hashes="['eb79224ac6d8e007b776848836321eaf', '51bea39b50c6b19f3eff3cbbb4d1b0f2', 'eb79224ac6d8e007b776848836321eaf']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(453478,1046) == "43ca2b90a3960693e6a65891cb36aff2"
}

