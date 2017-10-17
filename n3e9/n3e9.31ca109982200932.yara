import "hash"

rule n3e9_31ca109982200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca109982200932"
     cluster="n3e9.31ca109982200932"
     cluster_size="38 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['43a242136a15c960038a66cc5e7b8eaf', 'd70d56034e2547e44a4c30ed1d3e566e', 'ac53a4e42442cde8efbe603a4bd25a8e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(433997,1033) == "8ad58842a7a9a16ab3b93793b45a27c5"
}

