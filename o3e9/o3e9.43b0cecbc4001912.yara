import "hash"

rule o3e9_43b0cecbc4001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0cecbc4001912"
     cluster="o3e9.43b0cecbc4001912"
     cluster_size="232 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['ad0afc48f6b17ccfd9c5253eef1500a0', 'a557b04f2f4772aba782507232b52589', '0c904de9d08188fa1eab86cdf5b07e9c']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(823296,1024) == "87eb1721305da946a1b87ff9207f629a"
}

