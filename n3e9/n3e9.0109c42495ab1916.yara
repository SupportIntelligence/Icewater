import "hash"

rule n3e9_0109c42495ab1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c42495ab1916"
     cluster="n3e9.0109c42495ab1916"
     cluster_size="610 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="syncopate unwanted malicious"
     md5_hashes="['644e947bd89851cf7372f7363e46ca99', '2ff34ef0c7e2aae3f1cda26e6e8ada21', 'dfd5faa50341fa6fc142cbac3ba14ddc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(680448,1024) == "ead4a97ef9510bb7454b0dd619ef87bd"
}

