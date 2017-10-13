import "hash"

rule m3e9_118695a1ca000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.118695a1ca000932"
     cluster="m3e9.118695a1ca000932"
     cluster_size="166 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['63b21874557fa4d0916d6b0789923825', '1c663eb85540df794d3310e775cf2186', 'c77fefa299d58eeb8363cea930ae7722']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(36864,1024) == "be36e7d837001e86681445cdf3c7723f"
}

