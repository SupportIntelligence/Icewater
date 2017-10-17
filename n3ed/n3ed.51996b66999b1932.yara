import "hash"

rule n3ed_51996b66999b1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b66999b1932"
     cluster="n3ed.51996b66999b1932"
     cluster_size="36 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b17757d078dbf1ba2e87bc333283c810', 'c46d9224e0975006922b05232d3247ee', 'bca28c0304301fc0f197351a3c5ff987']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(340992,1024) == "dd91d06741e0bcecc34711b0e573b5c3"
}

