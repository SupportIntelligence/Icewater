import "hash"

rule n3e9_049d9ec1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.049d9ec1c4000932"
     cluster="n3e9.049d9ec1c4000932"
     cluster_size="218 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c75555610c4eeb8fec4f85bcbbfc34e9', '25f9b4e6cc48d8eabb51a4a7376b8a08', 'ce0dfe83fc136d2cf30b29d398ffce32']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(278528,1024) == "49fedfe9d66be3a6026b41fc3b0e9b08"
}

